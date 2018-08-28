# Sample job template

# Explanation of parameters

* **name**: Friendly-name of your job. It is mandatory field.
* **repo**: URL to the GIT repository.
* **branch**: GIT branch. Empty field means 'master' branch.
* **command**: Something you want to run. It is mandatory field.
* **owner**: Owner of your job. Owner will receive notifications about status of jobs execution.
* **schedule**: Schedule in Crontab notation. Empty field means one-time job.
* **targets**: Remote targets suitable for running this job.
	- Empty field means running on localhost.
	- Hostname resolved via DNS means running job via ssh.
	- URL to [Dockerfile](https://docs.docker.com/engine/reference/builder/) means running job inside Docker container.
	- URL to [Vagrantfile](https://www.vagrantup.com/docs/vagrantfile/) means running job inside Vagrant.
* **disabled**: State of your job. False by default.
* **dependent_jobs**:
* **parent_jobs**:

## Examples:

```json
{
	"name": "criu-test",
	"repo": "https://github.com/xemul/criu",
	"branch": "criu-dev",
	"command": "python test/zdtm.py run -a",
	"target": nil,
	"owner": "contacts@openvz.org",
	"disabled": false,
	"dependent_jobs": nil,
	"parent_jobs": nil,
	"schedule": "*/10 * * * * *",
}
```
