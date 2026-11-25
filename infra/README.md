# infra
> OSS-Fuzz project infrastructure

Core infrastructure:
* [`base-images`](base-images/) - docker images for building fuzz targets & corresponding jenkins
  pipeline.

Continuous Integration infrastructure:

* [`ci`](ci/) - script to build projects in CI.

## helper.py
> script to automate common docker operations

| Command | Description |
|---------|-------------
| `generate`      | Generates skeleton files for a new project |
| `validate-config` | Statically validates `project.yaml` and suggests fixes before builds |
| `generate-repro` | Generates an executable minimal local build/reproduce script |
| `build_image`   | Builds a docker image for a given project |
| `build_fuzzers` | Builds fuzz targets for a given project |
| `run_fuzzer`    | Runs a fuzz target in a docker container |
| `coverage`      | Runs fuzz target(s) in a docker container and generates a code coverage report. See [Code Coverage doc](https://google.github.io/oss-fuzz/advanced-topics/code-coverage/) |
| `reproduce`     | Runs a testcase to reproduce a crash |
| `shell`         | Starts a shell inside the docker image for a project |

Validate before spending CI/local hours on a build:

```bash
python3 infra/helper.py validate-config projects/<project>
```

Generate a minimal reproduction script and inspect its Docker-backed commands
without needing Docker installed:

```bash
python3 infra/helper.py generate-repro projects/<project> \
  --fuzzer <fuzz_target> --testcase <crash_file>
build/repro/<project>-reproduce.sh --dry-run
```

Run the offline acceptance scenario for three invalid configs and one valid
config:

```bash
bash acceptance/run_acceptance.sh
```
