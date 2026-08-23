// Jenkinsfile for Lariska Endpoint Inventory Agent
// Runs CI checks, formatting, clippy linting, unit/contract tests, and artifact builds inside Docker.

def RUST_IMAGE = 'rust:1-bookworm'
def RUST_DOCKER_ARGS = '-v lariska-cargo-home:/usr/local/cargo/registry -v lariska-cargo-target:/build-target'

pipeline {
    agent {
        docker {
            image RUST_IMAGE
            args RUST_DOCKER_ARGS
            reuseNode true
        }
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 20, unit: 'MINUTES')
    }

    stages {
        stage('Code Formatting') {
            steps {
                sh '''
                    set -eu
                    rustup component add rustfmt
                    cargo fmt --check
                '''
            }
        }

        stage('Clippy Linter') {
            steps {
                sh '''
                    set -eu
                    export CARGO_TARGET_DIR=/build-target
                    rustup component add clippy
                    cargo clippy --all-targets --all-features -- -D warnings
                '''
            }
        }

        stage('Unit & Contract Tests') {
            steps {
                sh '''
                    set -eu
                    export CARGO_TARGET_DIR=/build-target
                    cargo test --all-targets --all-features
                '''
            }
        }

        stage('Build Release Binary') {
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
            echo "✅ Lariska CI successfully passed on Jenkins :8081!"
        }
        failure {
            echo "❌ Lariska CI pipeline failed."
        }
    }
}
