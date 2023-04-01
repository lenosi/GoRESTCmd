# GoRESTCmd

GoRESTCmd is a straightforward web application that enables remote execution of shell commands through HTTP API requests. This web service offers multiple API endpoints for executing, monitoring the status, and retrieving output from executed commands.

## Features

* Execute shell commands remotely via HTTP API
* Retrieve the command output (stdout and stderr)
* Check the status of executed commands
* Limit concurrent command executions
* API key authentication

## Configuration

Create a config.json file in the root of the project with the following contents:

```yaml
api_key: "your-api-key",
concurrent_limit: 5,
port: 8080,
server_tls: false
server_cert_path: server.cert
server_key_path: server.key
allowed_commands: ["echo", "ping", "ls", "mkdir"]
```

Replace your-api-key with the actual API key you want to use. You can also adjust the concurrent_limit and port settings.

## Getting Started

### Prerequisites

* Go (1.20 or later)

### Building and Running

To build and run the Remote Executor, execute the following commands in the project root:

```sh
go build -o gorestcmd main.go
./gorestcmd
```

The Remote Executor service will start and listen on the configured port (default: 8080).

## API Endpoints

### POST /execute

Execute a shell command.

Request body:

```json
{
  "command": "your-command",
  "args": ["arg1", "arg2", "arg3"]
}
```

Response:

```text
Execution ID
```

### GET /execution/ID/result

Get the result of an executed command.

Response:

```json
{
  "stdout": "Command output",
  "stderr": "Command error output",
  "returnCode": 0,
  "startTime": "2023-04-01T00:00:00Z",
  "endTime": "2023-04-01T00:00:05Z",
  "elapsed": "5s",
  "status": "completed"
}
```

### GET /execution/ID/stdout

Get the stdout output of an executed command.

Response:

```text
Command output
```

### GET /execution/ID/stderr

Get the stderr output of an executed command.

Response:

```text
Command error output
```

### GET /execution/list

Get a list of executed commands and their statuses.

Response:

```json
{
  "1": "completed",
  "2": "running",
  "3": "canceled"
}
```

### POST /execution/cancel/ID

Cancel a running command.

Response:

```text
Execution canceled
```

## Tests

To run the tests, execute the following command in the project root:

```sh
go test -v
```

## License

This project is licensed under the MIT License
