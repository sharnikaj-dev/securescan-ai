export interface DemoSampleFile {
  filename: string;
  content: string;
}

export const DEMO_PROJECT_NAME = "DemoShop Vulnerable Microservice (Demo Mode)";

export const DEMO_SAMPLE_FILES: DemoSampleFile[] = [
  {
    filename: "auth_service.py",
    content: `import hashlib
import os
import pickle
import sqlite3
import subprocess
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
JWT_SECRET = "prod-jwt-signing-secret-99421"

def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT id, username, role FROM users WHERE username = '{username}'")
    return cur.fetchone()

def hash_legacy_password(raw_password: str) -> str:
    return hashlib.md5(raw_password.encode("utf-8")).hexdigest()

@app.route("/diag")
def run_diag():
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output

@app.route("/webhook")
def fetch_webhook():
    target_url = request.args.get("url")
    resp = requests.get(target_url, verify=False, timeout=5)
    return resp.text

@app.route("/session/restore", methods=["POST"])
def restore_session():
    raw_blob = request.get_data()
    return str(pickle.loads(raw_blob))

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "Guest")
    return render_template_string("<h1>Welcome " + name + "</h1>")

if __name__ == "__main__":
    app.run(debug=True)
`,
  },
  {
    filename: "profile_controller.ts",
    content: `import fs from "fs";
import path from "path";

export function renderBioPreview(container: HTMLElement, userBio: string) {
  container.innerHTML = userBio;
}

export function readAttachment(req: { query: { file: string } }) {
  const target = path.join("/var/uploads", req.query.file);
  return fs.readFileSync(target, "utf8");
}

export function logDebugToken(userId: string, apiKey: string) {
  console.log("Debug session for", userId, "apiKey=", apiKey);
}
`,
  },
  {
    filename: "native_parser.c",
    content: `#include <stdio.h>
#include <string.h>

void parse_header(const char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Header: %s\\n", buffer);
}
`,
  },
];
