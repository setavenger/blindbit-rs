use friglet_ipc::{Client, Request, Response, StatusInfo, accept, listen};

fn temp_socket_path() -> String {
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\friglet-ipc-test-{}", std::process::id())
    }
    #[cfg(not(windows))]
    {
        std::env::temp_dir()
            .join(format!("friglet-ipc-test-{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }
}

#[tokio::test]
async fn get_status_roundtrip() {
    let path = temp_socket_path();
    let listener = listen(&path).expect("bind test socket");

    let status = StatusInfo {
        scanning: true,
        scanned_height: 840_000,
        tip_height: Some(840_010),
        scan_progress: 0.99,
        network: "signet".to_string(),
        electrum_clients: 1,
        oracle_connected: true,
        last_error: None,
        sp_address: Some("sp1q...".to_string()),
        version: "0.1.0".to_string(),
    };
    let expected = status.clone();

    tokio::spawn(async move {
        let mut conn = accept(&listener).await.expect("accept");
        while let Some(req) = conn.next_request().await.expect("read request") {
            let resp = match req {
                Request::GetStatus => Response::Status(status.clone()),
                _ => Response::Ok,
            };
            conn.respond(&resp).await.expect("write response");
        }
    });

    let mut client = Client::connect(&path).await.expect("connect");
    let resp = client.request(&Request::GetStatus).await.expect("request");
    assert_eq!(resp, Response::Status(expected));

    let resp = client.request(&Request::Start).await.expect("request");
    assert_eq!(resp, Response::Ok);

    #[cfg(not(windows))]
    let _ = std::fs::remove_file(&path);
}
