//! End-to-end coverage for the optimized Step Functions API Gateway
//! integration (`arn:aws:states:::apigateway:invoke`): the task calls a REST
//! API through fakecloud's execute-api data plane, a 2XX answer is the task
//! output, and any other status fails the task with `ApiGateway.<status>`.

mod helpers;

use helpers::TestServer;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};

async fn wait_for_execution_full(
    client: &aws_sdk_sfn::Client,
    arn: &str,
) -> aws_sdk_sfn::operation::describe_execution::DescribeExecutionOutput {
    for _ in 0..200 {
        sleep(Duration::from_millis(50)).await;
        let desc = client
            .describe_execution()
            .execution_arn(arn)
            .send()
            .await
            .unwrap();
        if desc.status().as_str() != "RUNNING" {
            return desc;
        }
    }
    panic!("Execution did not complete in time: {arn}");
}

/// A REST API with `POST /items` answering 200 with `{"created":true}` from a
/// MOCK integration, deployed to stage `prod`.
async fn provision_items_api(client: &aws_sdk_apigateway::Client) -> String {
    let api = client
        .create_rest_api()
        .name("sfn-target")
        .send()
        .await
        .expect("create_rest_api");
    let api_id = api.id().unwrap().to_string();
    let root = api.root_resource_id().unwrap().to_string();
    let res_id = client
        .create_resource()
        .rest_api_id(&api_id)
        .parent_id(&root)
        .path_part("items")
        .send()
        .await
        .expect("create_resource")
        .id()
        .unwrap()
        .to_string();
    client
        .put_method()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("POST")
        .authorization_type("NONE")
        .send()
        .await
        .expect("put_method");
    client
        .put_integration()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("POST")
        .r#type(aws_sdk_apigateway::types::IntegrationType::Mock)
        .request_templates("application/json", r#"{"statusCode": 200}"#)
        .send()
        .await
        .expect("put_integration");
    client
        .put_method_response()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("POST")
        .status_code("200")
        .send()
        .await
        .expect("put_method_response");
    client
        .put_integration_response()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("POST")
        .status_code("200")
        .response_templates("application/json", r#"{"created":true}"#)
        .send()
        .await
        .expect("put_integration_response");
    client
        .create_deployment()
        .rest_api_id(&api_id)
        .stage_name("prod")
        .send()
        .await
        .expect("create_deployment");
    api_id
}

async fn run(
    server: &TestServer,
    name: &str,
    definition: Value,
) -> aws_sdk_sfn::operation::describe_execution::DescribeExecutionOutput {
    let sfn = server.sfn_client().await;
    let machine = sfn
        .create_state_machine()
        .name(name)
        .definition(definition.to_string())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .expect("create_state_machine");
    let execution = sfn
        .start_execution()
        .state_machine_arn(machine.state_machine_arn())
        .input(r#"{"item":{"id":"42","note":null}}"#)
        .send()
        .await
        .expect("start_execution");
    wait_for_execution_full(&sfn, execution.execution_arn()).await
}

#[tokio::test]
async fn sfn_apigateway_invoke_returns_the_response() {
    let server = TestServer::start().await;
    let api_id = provision_items_api(&server.apigateway_client().await).await;

    let definition = json!({
        "StartAt": "Call",
        "States": {"Call": {
            "Type": "Task",
            "Resource": "arn:aws:states:::apigateway:invoke",
            "Parameters": {
                "ApiEndpoint": format!("{api_id}.execute-api.us-east-1.amazonaws.com"),
                "Method": "POST",
                "Stage": "prod",
                "Path": "/items",
                "RequestBody": {"item.$": "$.item"},
                "AuthType": "NO_AUTH"
            },
            "ResultSelector": {
                "body.$": "$.ResponseBody",
                "status.$": "$.StatusCode",
                "text.$": "$.StatusText"
            },
            "End": true
        }}
    });
    let desc = run(&server, "apigw-invoke", definition).await;

    assert_eq!(desc.status().as_str(), "SUCCEEDED", "{:?}", desc.cause());
    let output: Value = serde_json::from_str(desc.output().unwrap()).unwrap();
    assert_eq!(
        output,
        json!({"body": {"created": true}, "status": 200, "text": "OK"})
    );
}

#[tokio::test]
async fn sfn_apigateway_invoke_fails_with_the_status_and_is_caught() {
    let server = TestServer::start().await;
    let api_id = provision_items_api(&server.apigateway_client().await).await;

    let definition = json!({
        "StartAt": "Call",
        "States": {
            "Call": {
                "Type": "Task",
                "Resource": "arn:aws:states:::apigateway:invoke",
                "Parameters": {
                    "ApiEndpoint": format!("{api_id}.execute-api.us-east-1.amazonaws.com"),
                    "Method": "GET",
                    "Stage": "prod",
                    "Path": "/missing"
                },
                "Catch": [{"ErrorEquals": ["ApiGateway.404"], "ResultPath": "$.failure", "Next": "Caught"}],
                "End": true
            },
            "Caught": {"Type": "Pass", "End": true}
        }
    });
    let desc = run(&server, "apigw-invoke-404", definition).await;

    assert_eq!(desc.status().as_str(), "SUCCEEDED", "{:?}", desc.cause());
    let output: Value = serde_json::from_str(desc.output().unwrap()).unwrap();
    assert_eq!(output["failure"]["Error"], "ApiGateway.404");
    let cause: Value = serde_json::from_str(output["failure"]["Cause"].as_str().unwrap()).unwrap();
    assert!(cause["message"].is_string(), "{cause}");
}

#[tokio::test]
async fn sfn_apigateway_invoke_sync_is_not_an_integration() {
    let server = TestServer::start().await;
    let definition = json!({
        "StartAt": "Call",
        "States": {"Call": {
            "Type": "Task",
            "Resource": "arn:aws:states:::apigateway:invoke.sync",
            "Parameters": {"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "GET"},
            "End": true
        }}
    });
    let desc = run(&server, "apigw-invoke-sync", definition).await;

    assert_eq!(desc.status().as_str(), "FAILED");
    assert_eq!(desc.error(), Some("States.TaskFailed"));
    assert!(desc.cause().unwrap().contains("Unsupported resource"));
}
