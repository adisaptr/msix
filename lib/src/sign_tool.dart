import 'dart:convert';
import 'dart:io';
import 'package:cli_dialog/cli_dialog.dart' show CLI_Dialog;
import 'package:cli_util/cli_logging.dart' show Logger;
import 'package:get_it/get_it.dart';
import 'package:path/path.dart' show extension, basename;
import 'extensions.dart';
import 'configuration.dart';

var _publisherRegex = RegExp(
    '(CN|L|O|OU|E|C|S|STREET|T|G|I|SN|DC|SERIALNUMBER|(OID.(0|[1-9][0-9]*)(.(0|[1-9][0-9]*))+))=(([^,+="<>#;])+|".*")(, ((CN|L|O|OU|E|C|S|STREET|T|G|I|SN|DC|SERIALNUMBER|(OID.(0|[1-9][0-9]*)(.(0|[1-9][0-9]*))+))=(([^,+="<>#;])+|".*")))*');

/// Handles the certificate sign functionality
class SignTool {
  final Logger _logger = GetIt.I<Logger>();
  final Configuration _config = GetIt.I<Configuration>();

  /// Use Powershell script to get the Publisher ("Subject") of the certificate
  Future<void> getCertificatePublisher() async {
    _logger.trace('getting certificate publisher');

    var powershellSubjectOutputFilePath =
        "${_config.msixAssetsPath}/subject.txt";

    var certificateDetailsProcess = await Process.run(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          "(Get-PfxData -FilePath \"${_config.certificatePath}\" -Password \$(ConvertTo-SecureString -String \"${_config.certificatePassword}\" -AsPlainText -Force)).EndEntityCertificates[0] | Format-List -Property Subject | Out-File -NoNewLine -Width 8192 -Encoding UTF8 -FilePath \"$powershellSubjectOutputFilePath\""
        ],
        stdoutEncoding: utf8,
        stderrEncoding: utf8);

    if (certificateDetailsProcess.exitCode != 0) {
      _logger.stderr(certificateDetailsProcess.stdout);
      throw certificateDetailsProcess.stderr;
    }

    var powershellSubjectOutputFile = File(powershellSubjectOutputFilePath);

    if (!await powershellSubjectOutputFile.exists()) {
      throw 'cannot get certificate subject'.red;
    }

    var subjectRow = await powershellSubjectOutputFile.readAsString();
    await powershellSubjectOutputFile.deleteIfExists();

    if (!_publisherRegex.hasMatch(subjectRow)) {
      throw 'invalid certificate subject: $subjectRow';
    }

    _config.publisher = subjectRow
        .substring(subjectRow.indexOf(':') + 1, subjectRow.length)
        .trim();
  }

  /// Use Powershell to install the test certificate
  /// if needed and if the user want to.
  Future<void> installCertificate() async {
    var getInstalledCertificate = await Process.run('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      "dir Cert:\\CurrentUser\\Root | Where-Object { \$_.Subject -eq  '${_config.publisher}'}"
    ]);

    if (getInstalledCertificate.exitCode != 0) {
      _logger.stderr(getInstalledCertificate.stdout);
      throw getInstalledCertificate.stderr;
    }

    var isCertificateNotInstalled =
        getInstalledCertificate.stdout.toString().isNullOrEmpty;

    if (isCertificateNotInstalled) {
      _logger.trace('installing certificate');

      _logger.stdout('');
      final dialog = CLI_Dialog(booleanQuestions: [
        [
          'Do you want to install the certificate: "${basename(File(_config.certificatePath!).path)}" ?',
          'install'
        ]
      ]);
      final wantToInstallCertificate = dialog.ask()['install'];

      if (wantToInstallCertificate) {
        // create installCertificate.ps1 file
        var installCertificateScript =
            'Import-PfxCertificate -FilePath "${_config.certificatePath}" -Password (ConvertTo-SecureString -String "${_config.certificatePassword}" -AsPlainText -Force) -CertStoreLocation Cert:\\LocalMachine\\Root';
        var installCertificateScriptPath =
            '${_config.msixAssetsPath}/installCertificate.ps1';
        await File(installCertificateScriptPath)
            .writeAsString(installCertificateScript);

        // then execute it with admin privileges
        var importCertificate = await Process.run('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          'Start-Process powershell -ArgumentList "$installCertificateScriptPath" -Wait -Verb runAs -WindowStyle Hidden'
        ]);

        await File(installCertificateScriptPath).deleteIfExists();

        if (importCertificate.exitCode != 0) {
          var error = importCertificate.stderr.toString();
          if (error.contains('was canceled by the user')) {
            _logger.stderr('the certificate installation was canceled'.red);
          } else {
            throw error;
          }
        } else {
          _logger.stdout('the certificate installed successfully '.green);
        }
      }
    }
  }

  /// Sign the MSIX file with the certificate
  Future<void> sign() async {
    _logger.trace('signing');

    String signToolPath = p.join(_config.msixToolkitPath, 'signtool.exe');
    final signToolOptions = getSignToolOptions();
    bool isFullSignToolCommand =
        signToolOptions[0].toLowerCase().contains('signtool');

    // ignore: avoid_single_cascade_in_expression_statements
    await Process.run(
        isFullSignToolCommand ? signToolOptions[0] : signToolPath, [
      if (!isFullSignToolCommand) 'sign',
      ...signToolOptions.skip(isFullSignToolCommand ? 1 : 0),
      _config.msixPath,
    ])
      ..exitOnError();
  }

  /// Returns the options necessary for [sign].
  ///
  /// This method accounts for whether the config already has signtool options
  /// that [isCustomSignCommand] and the config's certificate type.
  List<String> getSignToolOptions() {
    List<String> signToolOptions = _config.signToolOptions ?? ['/v'];

    if (isCustomSignCommand(_config.signToolOptions)) {
      signToolOptions = _config.signToolOptions!;
    } else if (_config.certificatePath != null) {
      switch (extension(_config.certificatePath!).toLowerCase()) {
        case '.pfx':
          signToolOptions.addAll(['/p', _config.certificatePassword!]);
          break;
        default:
          signToolOptions.addAll(['/a']);
      }

      signToolOptions.addAll([
        '/fd',
        'SHA256',
        '/td',
        'SHA256',
        '/tr',
        'http://timestamp.digicert.com',
        '/f',
        _config.certificatePath!,
      ]);
    }

    return signToolOptions;
  }

  static isCustomSignCommand(List<String>? signToolOptions) =>
      signToolOptions != null &&
      signToolOptions.isNotEmpty &&
      signToolOptions.containsArguments(['/sha1', '/n', '/r', '/i', '/f']);
}
