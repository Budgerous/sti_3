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

## Explanation

The `ChatServer` class acts like a daemon, you don't really send messages through it.
Create multiple `ChatClient` instances and communicate between them.
