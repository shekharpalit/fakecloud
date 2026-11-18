//! CreateFunction and UpdateFunctionCode with code in S3 (`S3Bucket`,
//! `S3Key`, optional `S3ObjectVersion`): Lambda reads the object, so the
//! function's code is that object's bytes, as Terraform deploys packages.

mod helpers;

use std::io::Write;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use helpers::TestServer;
use sha2::{Digest, Sha256};

fn zip_of(source: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file("index.py", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(source.as_bytes()).unwrap();
    writer.finish().unwrap().into_inner()
}

fn sha256_b64(bytes: &[u8]) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        Sha256::digest(bytes),
    )
}

async fn put_versions(server: &TestServer, first: &[u8], second: &[u8]) -> (String, String) {
    let s3 = server.s3_client().await;
    s3.create_bucket().bucket("code").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("code")
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let mut versions = Vec::new();
    for body in [first, second] {
        let put = s3
            .put_object()
            .bucket("code")
            .key("fn.zip")
            .body(aws_sdk_s3::primitives::ByteStream::from(body.to_vec()))
            .send()
            .await
            .unwrap();
        versions.push(put.version_id().unwrap().to_string());
    }
    (versions.remove(0), versions.remove(0))
}

fn code_from_s3(version: Option<&str>) -> FunctionCode {
    FunctionCode::builder()
        .s3_bucket("code")
        .s3_key("fn.zip")
        .set_s3_object_version(version.map(str::to_string))
        .build()
}

#[tokio::test]
async fn create_function_reads_its_code_from_s3() {
    let server = TestServer::start().await;
    let first = zip_of("def handler(event, context):\n    return 1\n");
    let second = zip_of("def handler(event, context):\n    return 2\n");
    let (first_version, _) = put_versions(&server, &first, &second).await;
    let lambda = server.lambda_client().await;

    for (name, version, expected) in [
        ("latest", None, &second),
        ("requested-version", Some(first_version.as_str()), &first),
    ] {
        let created = lambda
            .create_function()
            .function_name(name)
            .runtime(Runtime::Python312)
            .role("arn:aws:iam::123456789012:role/test-role")
            .handler("index.handler")
            .code(code_from_s3(version))
            .send()
            .await
            .unwrap();
        assert_eq!(created.code_size(), expected.len() as i64, "{name}");
        assert_eq!(
            created.code_sha256(),
            Some(sha256_b64(expected).as_str()),
            "{name}"
        );
    }
}

#[tokio::test]
async fn create_function_refuses_a_missing_s3_object() {
    let server = TestServer::start().await;
    server
        .s3_client()
        .await
        .create_bucket()
        .bucket("code")
        .send()
        .await
        .unwrap();
    let error = server
        .lambda_client()
        .await
        .create_function()
        .function_name("missing")
        .runtime(Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(code_from_s3(None))
        .send()
        .await
        .unwrap_err();
    let service_error = error.into_service_error();
    assert!(
        service_error.is_invalid_parameter_value_exception(),
        "{service_error:?}"
    );
}

#[tokio::test]
async fn update_function_code_reads_the_requested_s3_version() {
    let server = TestServer::start().await;
    let first = zip_of("def handler(event, context):\n    return 1\n");
    let second = zip_of("def handler(event, context):\n    return 2\n");
    let (first_version, _) = put_versions(&server, &first, &second).await;
    let lambda = server.lambda_client().await;
    lambda
        .create_function()
        .function_name("updated")
        .runtime(Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            FunctionCode::builder()
                .zip_file(Blob::new(zip_of("def handler(e, c):\n    return 0\n")))
                .build(),
        )
        .send()
        .await
        .unwrap();

    let updated = lambda
        .update_function_code()
        .function_name("updated")
        .s3_bucket("code")
        .s3_key("fn.zip")
        .s3_object_version(&first_version)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.code_sha256(), Some(sha256_b64(&first).as_str()));
}
