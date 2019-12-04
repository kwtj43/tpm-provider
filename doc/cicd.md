# GitLab CI/CD
Gitlab has been configured to build and test the tpm-provider repository.  This entials the setup and management of gitlab-runners with specific configurations.

|Stage|Description|
|--------|-----------|
|build|This stage will compile the project and optionally create artifacts that can be downloaded from GitLab.  |
|test|This state will run the unit tests |

# 'build' gitlab-runner setup
When the 'build' stage is run by gitlab-runner, the .gitlab-ci.yml is configured to start a docker container using the `gta-devel` image (containing required dependencies like Tss2).  Running `make` or `go build` does not require any other processes to be run, so this stage follows the 'normal' operations needed by gitlab (unlike the 'test' stage described below). 

To setup a 'build' stage gitlab-runner...
1) Make sure the host that will run the gitlab-runner has docker and `gta-devel` image installed (see [Compiling tpm-provider](build.md#Compiling-tpm-provider) for instructions on creating `gta-devel`).
2.) Install see: GitLab Runner on the host...
	a) Install git on the host

	b) Download the gitlab-runner rpm: ```curl -LJO https://gitlab-runner-downloads.s3.amazonaws.com/latest/rpm/gitlab-runner_amd64.rpm```

	c) Install rpm: ```rpm -i gitlab-runner_amd64.rpm```

	d) Run ```gitlab-runner register``` with the token from the gitlab and tag 'gta' (required by the 'build' stage in .gitlab-ci.yml).

		[root@e80f5883f540 tmp]# gitlab-runner register
		Runtime platform arch=amd64 os=linux pid=152 revision=05161b14 version=12.4.1
		Running in system-mode.                            
															
		Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
		https://gitlab.devtools.intel.com/
		Please enter the gitlab-ci token for this runner:
		eaMZBFY3yk-a2DFmVfd6
		Please enter the gitlab-ci description for this runner:
		[e80f5883f540]: 168.220-gta-devel-build
		Please enter the gitlab-ci tags for this runner (comma separated):
		gta-unit-test
		Registering runner... succeeded                     runner=eaMZBFY3
		Please enter the executor: shell, ssh, virtualbox, docker-ssh+machine, docker, parallels, docker+machine, kubernetes, custom, docker-ssh:
		docker
		Please enter the default Docker image (e.g. ruby:2.6):
		gta-devel
		Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!

	e) Add 'pull_policy' to 'never' in config.toml so that gitlab-runner doesn't attempt to pull docker images  (this is a locally installed image of `gta-devel`).

		[root@localhost home]# vi /etc/gitlab-runner/config.toml 
		concurrent = 1
		check_interval = 0

		[session_server]
		session_timeout = 1800

		[[runners]]
		name = "kentthom-devel-160-63"
		url = "https://gitlab.devtools.intel.com"
		token = "4oZKDT5DuZRKu7xu8g4D"
		executor = "docker"
		[runners.custom_build_dir]
		[runners.docker]
			tls_verify = false
			image = "gta-devel"
			privileged = false
			pull_policy = "never"
			disable_entrypoint_overwrite = false
			oom_kill_disable = false
			disable_cache = false
			volumes = ["/cache"]
			shm_size = 0
		[runners.cache]
			[runners.cache.s3]
			[runners.cache.gcs]

# 'test' gitlab-runner setup
The following instructions describe how to setup a gitlab-runner that executes the tpmprovider unit tests.  The unit test use the tpm simulator, which must run in the background along with tpm2-abrmd service (requiring systemd).  Unfortunately, there's isn't a way to run 'out-of-the-box' gitlab-runners with systemd.  The solution empoyed entails creating a 'gta-devel' docker container (running systemd) that has the gitlab-runner installed using the 'ssh' protocol.

1) Make sure the host that will run the gitlab-runner has docker and `gta-devel` image installed (see [Compiling tpm-provider](build.md#Compiling-tpm-provider) for instructions on creating `gta-devel`).
2) Create a docker container, running in the background that exposes port 22 (for gitlab's ssh communications)

    ```docker run --name gta-devel-gitlab -d --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -p 10022:22 gta-devel /usr/sbin/init &```

3) Attach to the container (`docker exec -it {container id} /bin/bash`).

4) Use ```passwd``` to change the root password that can be used during 'gitlab-runner register' below.

5) Edit ```.bash_profile``` to include proxy settings.

    ```export http_proxy=http://proxy-us.intel.com:911```

    ```export https_proxy=http://proxy-us.intel.com:911```

    ```export no_proxy=gitlab.devtools.intel.com```
6) Git config with proxy settings. *Note: gitlab-runners/.gitlab-ci.yml deploy a token that is used to authorize access to git access during builds.*

	```git config --global http.proxy http://proxy-us.intel.com:911```

	```git config --global https.proxy http://proxy-us.intel.com:911```

7) Install and start ssh in container.

    ```yum install openssh-server```
   
    ```systemctl start sshd```
	
	Make sure you can ssh to container remotely: ```ssh root@(host address) -p 10022```

8) Install see: GitLab Runner on the container...

	a) Download the gitlab-runner rpm: ```curl -LJO https://gitlab-runner-downloads.s3.amazonaws.com/latest/rpm/gitlab-runner_amd64.rpm```

	b) Install rpm: ```rpm -i gitlab-runner_amd64.rpm```

	c) Run ```gitlab-runner register``` with the token from the gitlab and tag 'gta-unit-test' (required by the 'test' stage in .gitlab-ci.yml)

		[root@e80f5883f540 tmp]# gitlab-runner register
		Runtime platform arch=amd64 os=linux pid=152 revision=05161b14 version=12.4.1
		Running in system-mode.                            
		                                                   
		Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
		https://gitlab.devtools.intel.com/
		Please enter the gitlab-ci token for this runner:
		eaMZBFY3yk-a2DFmVfd6
		Please enter the gitlab-ci description for this runner:
		[e80f5883f540]: 168.220-gta-devel-test
		Please enter the gitlab-ci tags for this runner (comma separated):
		gta-unit-test
		Registering runner... succeeded                     runner=eaMZBFY3
		Please enter the executor: shell, ssh, virtualbox, docker-ssh+machine, docker, parallels, docker+machine, kubernetes, custom, docker-ssh:
		ssh
		Please enter the SSH server address (e.g. my.server.com):
		{HOST_IP}
		Please enter the SSH server port (e.g. 22):
		10022
		Please enter the SSH user (e.g. root):
		root
		Please enter the SSH password (e.g. docker.io):
		ROOT_PASSWWORD
		Please enter path to SSH identity file (e.g. /home/user/.ssh/id_rsa):
        
        Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!