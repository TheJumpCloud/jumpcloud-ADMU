const {
    createHash,
  } = require('node:crypto');
  const {
    readFile,
    writeFile,
  } = require('node:fs').promises;
  const {
    basename
  } = require('node:path');
  const {
    HeadObjectCommand,
    NotFound,
    PutObjectCommand,
    S3Client,
  } = require('@aws-sdk/client-s3');

  async function ensureNotExists(core, client, bucket, key) {
    try {
      const command = new HeadObjectCommand({
        Bucket: bucket,
        Key: key,
      });

      core.info(`Checking if exists: ${bucket}/${key}`);
      await client.send(command);
      core.setFailed(`File already exists: ${bucket}/${key}`);
      process.exit(1);
    } catch (err) {
      if (!(err instanceof NotFound)) {
        core.setFailed(`Check if file exists in S3 failed with error ${err}`);
        process.exit(1);
      }
    }
  }

  async function putIfNotExists(core, client, config, key, file) {
    await ensureNotExists(core, client, config.s3Bucket, key);

    try {
      const data = await readFile(file);
      const command = new PutObjectCommand({
        Body: data,
        Bucket: config.s3Bucket,
        ContentMD5: createHash('md5').update(data).digest('base64'),
        Key: key,
      });

      if (config.s3ObjectLockEnabled) {
        const retainLockUntil = new Date();
        retainLockUntil.setFullYear(retainLockUntil.getFullYear() + parseInt(config.s3ObjectLockYears));

        command.ObjectLockMode = 'COMPLIANCE';
        command.ObjectLockRetainUntilDate = retainLockUntil;
      }

      core.info(`Uploading: ${config.s3Bucket}/${key}`);
      const resp = await client.send(command);
      core.info(`Uploaded: ${config.s3Bucket}/${key}`);

      return {
        bucket: config.s3Bucket,
        etag: resp.ETag,
        key: key,
        md5: createHash('md5').update(data).digest('hex'),
        sha256: createHash('sha256').update(data).digest('hex'),
      };
    } catch (err) {
      core.setFailed(`Upload to S3 failed with error ${err}`);
      process.exit(1);
    }
  }

  function createManifestFileName(core) {
    const manifestBaseName = 'manifest';
    const manifestExt = '.json';

    let manifestName = '';
    let manifestNumber;

    if (process.env.MANIFEST_NUMBER) {
      manifestNumber = parseInt(process.env.MANIFEST_NUMBER);
      manifestName = `${manifestBaseName}_${manifestNumber}${manifestExt}`;
    } else {
      manifestNumber = 0;
      manifestName = `${manifestBaseName}${manifestExt}`;
    }
    manifestNumber += 1;
    core.exportVariable('MANIFEST_NUMBER', manifestNumber.toString());
    return manifestName;
  }

  async function createManifest(core, config, manifestFileName, signedUploadedFiles, unsignedUploadedFiles) {
    const token = await core.getIDToken();
    const gh_token = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());

    const runner_info = {
      runner_arch: config.runnerArch,
      runner_name: config.runnerName,
      runner_os: config.runnerOs,
    };

    const manifest = {
      build_info: {
        gh_token,
        runner_info,
      },
      artifacts: [],
    };

    const addArtifact = function(file, signed) {
      const artifact = {
        bucket: file.bucket,
        etag: file.etag,
        key: file.key,
        md5: file.md5,
        platform: config.platform,
        sha256: file.sha256,
        signed: signed,
      };
      manifest.artifacts.push(artifact);
    }

    for (const file of signedUploadedFiles) {
      addArtifact(file, true);
    }

    for (const file of unsignedUploadedFiles) {
      addArtifact(file, false);
    }

    const manifestJSON = JSON.stringify(manifest, null, 2);
    await writeFile(manifestFileName, manifestJSON);
    core.info(`Signing manifest ${manifestFileName}:\n${manifestJSON}`);
  }

  function getConfig() {
    const {
      GITHUB_REF_NAME,
      GITHUB_REPOSITORY,
      GITHUB_SHA,
      IS_RELEASE_BUILD,
      OBJECT_LOCK_ENABLED,
      OBJECT_LOCK_YEARS,
      PRERELEASE_ARTIFACT_BUCKET,
      PRERELEASE_ARTIFACT_BUCKET_REGION,
      RUNNER_ARCH,
      RUNNER_NAME,
      RUNNER_OS,
      ADMU_VERSION,
    } = process.env

    const buildType = IS_RELEASE_BUILD === 'true' ? `release/${ADMU_VERSION}` : 'dev';
    const shortSha = GITHUB_SHA.substring(0, 10);
    const platform = RUNNER_OS.toLowerCase();

    return {
      platform,
      runnerArch: RUNNER_ARCH,
      runnerName: RUNNER_NAME,
      runnerOs: RUNNER_OS,
      s3Bucket: PRERELEASE_ARTIFACT_BUCKET,
      s3KeyPrefix: `${GITHUB_REPOSITORY}/${buildType}/${shortSha}/${platform}`,
      s3ObjectLockEnabled: OBJECT_LOCK_ENABLED === 'true',
      s3ObjectLockYears: OBJECT_LOCK_YEARS,
      s3Region: PRERELEASE_ARTIFACT_BUCKET_REGION,
    }
  }

  module.exports = async (core, filesInput, uploadOnlyFilesInput) => {
    if (!filesInput && !uploadOnlyFilesInput) {
      core.setFailed('No files provided');
      process.exit(1);
    }

    const config = getConfig();
    const s3Client = new S3Client({region: config.s3Region});

    const uploadedSigned = [];
    if (filesInput) {
      for (const file of filesInput.split('\n')) {
        const filename = basename(file);
        const binaryKey = `${config.s3KeyPrefix}/${filename}`;

        const metadata = await putIfNotExists(core, s3Client, config, binaryKey, file);
        uploadedSigned.push(metadata);

        if (config.platform === 'linux') {
          await putIfNotExists(core, s3Client, config, `${binaryKey}.sig`, `${file}.sig`);
        }
      }
    }

    const uploadedOnly = [];
    if (uploadOnlyFilesInput) {
      for (const file of uploadOnlyFilesInput.split('\n')) {
        const filename = basename(file);
        const fileKey = `${config.s3KeyPrefix}/${filename}`;
        const metadata = await putIfNotExists(core, s3Client, config, fileKey, file);
        uploadedOnly.push(metadata)
      }
    }

    const manifestFileName = createManifestFileName(core);
    await createManifest(core, config, manifestFileName, uploadedSigned, uploadedOnly);
    await putIfNotExists(core, s3Client, config, `${config.s3KeyPrefix}/${manifestFileName}`, manifestFileName);
  };