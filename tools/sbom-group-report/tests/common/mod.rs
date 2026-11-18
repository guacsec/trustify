// A broken assumption here is a broken test, not a runtime fault, so the
// helper panics rather than threading errors through the handler signature.
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::Value;

#[derive(Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

pub struct Server {
    pub url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    pub fn new(mut handler: impl FnMut(&str, &Request) -> Value + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread = {
            let url = url.clone();
            let requests = requests.clone();
            let stopped = stopped.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopped.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut stream = stream.unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(&mut stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let mut words = line.split_whitespace();
                    let method = words.next().unwrap().to_owned();
                    let path = words.next().unwrap().to_owned();
                    let mut headers = BTreeMap::new();
                    loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        let (name, value) = line.split_once(':').unwrap();
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                    }
                    let length = headers
                        .get("content-length")
                        .map_or(0, |value| value.parse().unwrap());
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let request = Request {
                        method,
                        path,
                        headers,
                        body: String::from_utf8(body).unwrap(),
                    };
                    requests.lock().unwrap().push(request.clone());
                    let response = handler(&url, &request).to_string();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
                }
            })
        };
        Self {
            url,
            requests,
            stopped,
            thread: Some(thread),
        }
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
