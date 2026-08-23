// Jenkinsfile for Lariska Endpoint Inventory Agent
// Runs CI checks, formatting, clippy linting, security audits, unit/contract tests, and artifact builds inside Docker.

def RUST_IMAGE = 'rust:1-bookworm'
def RUST_DOCKER_ARGS = '-v lariska-cargo-home:/usr/local/cargo/registry -v lariska-cargo-target:/build-target'

pipeline {
    agent none

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 20, unit: 'MINUTES')
    }

    stages {
        stage('Quality Gate') {
            parallel {
                stage('Code Formatting (cargo fmt)') {
                    agent {
                        docker {
                            image RUST_IMAGE
                            args RUST_DOCKER_ARGS
                            reuseNode true
                        }
                    }
                    steps {
                        sh '''
                            set -eu
                            rustup component add rustfmt
                            cargo fmt --check
                        '''
                    }
                }

                stage('Linter (cargo clippy)') {
                    agent {
                        docker {
                            image RUST_IMAGE
                            args RUST_DOCKER_ARGS
                            reuseNode true
                        }
                    }
                    steps {
                        sh '''
                            set -eu
                            export CARGO_TARGET_DIR=/build-target
                            rustup component add clippy
                            cargo clippy --all-targets --all-features -- -D warnings
                        '''
                    }
                }

                stage('Secrets Scan (gitleaks)') {
                    agent any
                    steps {
                        sh '''
                            set -eu
                            NO_GIT=""
                            [ -d .git ] || NO_GIT="--no-git"
                            docker run --rm -v "$WORKSPACE":/src -w /src zricethezav/gitleaks:v8.30.1 \
                                detect --source /src $NO_GIT \
                                  --report-format json --report-path /src/gitleaks.json \
                                  --redact --no-banner --exit-code 1 || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'gitleaks.json', allowEmptyArchive: true
                        }
                    }
                }
            }
        }

        stage('Unit & Contract Tests') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
            }
            steps {
                sh '''
                    set -eu
                    export CARGO_TARGET_DIR=/build-target
                    cargo test --all-targets --all-features
                '''
            }
        }

        stage('Build Release Binary') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
            }
            steps {
                sh '''
                    set -eu
                    export CARGO_TARGET_DIR=/build-target
                    cargo build --release
                    cp /build-target/release/lariska ./lariska-bin
                    ./lariska-bin --help
                '''
            }
            post {
                success {
                    archiveArtifacts artifacts: 'lariska-bin', allowEmptyArchive: false, fingerprint: true
                }
            }
        }
    }

    post {
        success {
            echo "✅ Lariska CI successfully passed on Jenkins!"
        }
        failure {
            echo "❌ Lariska CI pipeline failed."
        }
    }
}
