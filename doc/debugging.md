## Go and C Debugging
Visual Studio Code Insiders contains the 'Remote Development' extension that provides go/c debugging in the 'gta-devel' container (using the Microsoft TPM simulator).

1. Create a new `gta-devel` container that starts systemd (see [Compiling tpm-provider](build.md#Compiling-tpm-provider) for instructions on creating a `gta-devel` container).
    * cd to the root the code base
    * Run `docker run --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v $(pwd):/docker_host -p 9443:1443 gta-devel /usr/sbin/init`
2. Go to vscode's docker tab, right click on the new container and select 'Attach Visual Studio Code'.  A new vscode window will open.  Open the '/docker_host' folder which is the local source repo mounted in the container.
3. In the new vscode window, install the C++ and Go extensions (i.e. they will be installed for debugging on the container). 
4. Add the following debug configuration to `.vscode/launch.json` that will launch '`tagent setup takeownership`'.
    ```
    {
        "name": "GTA: (gdb) Launch",
        "type": "cppdbg",
        "request": "launch",
        "program": "${workspaceFolder}/go-trust-agent/out/tagent",
        "args": ["setup", "takeownership"],
        "stopAtEntry": false,
        "cwd": "${workspaceFolder}/go-trust-agent/out/",
        "environment": [],
        "externalConsole": false,
        "MIMode": "gdb",
        "setupCommands": [
            {
                "description": "Enable pretty-printing for gdb",
                "text": "-enable-pretty-printing",
                "ignoreFailures": true
            }
        ]
    }
    ```
5. Start the TPM simulator and tpm-abrmd: `cicd\start-tpm-simulator.sh` (the script will report "OK" if everything is started correctly).
6. Build GTA in the debug container (i.e. `make` from the go-trust-agent directory).  
    * Note: This requires that git configuration and ssh keys.
    * Note: Run `make installer` the first time and run `out/trustagent-v1.0.0.bin` without a trustagent.env file.  This will create folders needed in /opt/trustagent but not start the tagent service (the debugger will be used to start/stop the service).
7. Debug:  Set breakpoints in go or code, go to vscode's debug tab and select the name of the target (in this case 'GTA:(gdb) Launch').  Click the 'Start Debugging' button.  Repeat setps 6, 7 and 8 as needed.

*Note: Currently it is not possible to provision GTA (`tagent setup`) due to the fact that the TPM simulator does not come with a manufacture's endorsement key.  The missing EK results in an error during `provision-ek` setup task.