# WARNING: THIS IS WORK IN PROGRESS. IT DOES NOT WORK RIGHT NOW


# trivy-plugin-sonarcloud

A [Trivy](https://github.com/aquasecurity/trivy) plugin that converts JSON report to [SonarCloud](https://sonarcloud.io) format. The idea is to scan project dependencies with Trivy and post results to SonarCloud through external issues report. This way you can get code scanning and dependency scanning results in one place.


## Installation

install plugin:
```
$ trivy plugin install github.com/kahennig/trivy-plugin-sonarcloud
```

check the installation:
```
$ trivy plugin list
```

NOTE: you need [Python](https://www.python.org/) interpreter installed to be able to run plugin.


## Usage

run `trivy` with JSON report enabled:
```
$ trivy fs --format=json --output=trivy.json PATH
```

convert Trivy report to SonarCloud compatible report:
```
$ trivy sonarcloud trivy.json > sonarcloud.json
```

redefine `filePath` field of SonarCloud result. For example, if you scan Dockerfile with `trivy image` command, `filePath` field will contain url of docker image instead of file name. As result, SonarCloud will skip this report, because docker image url is not a source file in terms of SonarCloud. `--filePath` option allows you to set Dockefile name:
```
$ trivy sonarcloud trivy.json -- filePath=Dockerfile > sonarcloud.json
```

## GitLab CI

Here is a small example how to use this plugin in GitLab CI to post Trivy results to SonarCloud.

```
scan-deps:
  stage: scan
  image:
    name: aquasec/trivy
    entrypoint: [""]
  before_script:
    - apk add --no-cache python3
    - trivy plugin install github.com/umax/trivy-plugin-sonarcloud
  script:
    - trivy fs
      --security-checks=vuln
      --vuln-type=library
      --exit-code=0
      --format=json
      --output=trivy-deps-report.json
      .
    - trivy sonarcloud trivy-deps-report.json > sonar-deps-report.json
  artifacts:
    paths:
      - trivy-deps-report.json
      - sonar-deps-report.json

scan-code:
  stage: scan
  image: sonarsource/sonar-scanner-cli
  needs:
    - scan-deps
  script:
    - sonar-scanner -D sonar.externalIssuesReportPaths="sonar-deps-report.json" ...
```
