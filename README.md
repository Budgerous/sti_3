# sti_3

## Compiling instructions

### From command line/bash/whatever

`javac ./src/ChatServer.java -d ./out/production/sti_3/`

`javac ./src/ChatClient.java -d ./out/production/sti_3/`

### From IntelliJ

`Ctrl` + `F9`

## Running instructions

### From command line/bash/whatever

`java -cp ./out/production/sti_3 ChatServer <port>`

`java -cp ./out/production/sti_3 ChatClient localhost <port>`

### From IntelliJ

Create a Configuration based on `Application`, with Main class `ChatServer`. Program arguments should be a port (e.g. `5678`). Then, run it.

Create a Configuration based on `Application`, with Main class `ChatClient`. Program arguments should be the host of the server (probably `localhost`) and the port where it's listening (e.g. `5678`). Then, run it.

## Explanation

The `ChatServer` class acts like a daemon, you don't really send messages through it.
Create multiple `ChatClient` instances and communicate between them.
