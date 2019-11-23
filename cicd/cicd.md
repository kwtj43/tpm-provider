# CICD

## gitlab-runner setup
The following instructions describe how to setup a gitlab-runner that executes the tpmprovider unit tests.  The unit test use the tpm simulator, which must run in the background along with tpm2-abrmd service (requiring systemd).  Unfortunately, there's isn't a way to run 'out-of-the-box' gitlab-runners with systemd.  The solution empoyed entails creating a 'gta-devel' docker container (running systemd) that has the gitlab-runner installed using the 'ssh' protocol.

1) Create a docker container that exposes port 22 (for gitlab's ssh communications)

    ```docker run --name gta-devel-gitlab -d --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -p 10022:22 gta-devel /usr/sbin/init```

2) Install and start ssh in container.

    ```yum install openssh-server```
   
    ```systemctl start sshd```

3) Use ```passwd``` to change the root password
4) Edit ```.bash_profile``` to include proxy settings.

    ```export http_proxy=http://proxy-us.intel.com:911```

    ```export https_proxy=http://proxy-us.intel.com:911```

    ```export no_proxy=gitlab.devtools.intel.com```
5) Git config with proxy settings

	```git config --global http.proxy http://proxy-us.intel.com:911```

	```git config --global https.proxy http://proxy-us.intel.com:911```

	```git config --global url."ssh://git@gitlab.devtools.intel.com:29418".insteadOf https://gitlab.devtools.intel.com```

6) Make sure you can ssh to container remotely: ```ssh root@(host address) -p 10022```
7) Install see: GitLab Runner on the container

	a) Download the gitlab-runner rpm: ```curl -LJO https://gitlab-runner-downloads.s3.amazonaws.com/latest/rpm/gitlab-runner_amd64.rpm```

	b) Install rpm: ```rpm -i gitlab-runner_amd64.rpm```

	c) Run ```gitlab-runner register``` with the token from the gitlab and tag 'gta-unit-test' (specified in .gitlab-ci.yml)

		[root@e80f5883f540 tmp]# gitlab-runner register
		Runtime platform arch=amd64 os=linux pid=152 revision=05161b14 version=12.4.1
		Running in system-mode.                            
		                                                   
		Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
		https://gitlab.devtools.intel.com/
		Please enter the gitlab-ci token for this runner:
		eaMZBFY3yk-a2DFmVfd6
		Please enter the gitlab-ci description for this runner:
		[e80f5883f540]: 167.63-gta-devel-gitlab
		Please enter the gitlab-ci tags for this runner (comma separated):
		gta-unit-test
		Registering runner... succeeded                     runner=eaMZBFY3
		Please enter the executor: shell, ssh, virtualbox, docker-ssh+machine, docker, parallels, docker+machine, kubernetes, custom, docker-ssh:
		ssh
		Please enter the SSH server address (e.g. my.server.com):
		HOST_IP
		Please enter the SSH server port (e.g. 22):
		10022
		Please enter the SSH user (e.g. root):
		root
		Please enter the SSH password (e.g. docker.io):
		ROOT_PASSWWORD
		Please enter path to SSH identity file (e.g. /home/user/.ssh/id_rsa):
        
        Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!