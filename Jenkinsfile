pipeline {
    agent any
    parameters {
        string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Branch to build')
        string(name: 'IMAGE_VERSION', defaultValue: 'latest', description: 'Docker image version tag')
        string(name: 'VAULT_ADDR', defaultValue: 'https://vault.downops.win', description: 'Vault server address')
        string(name: 'VAULT_SECRET_PATH', defaultValue: 'secret/wallet-tracker/backend', description: 'Vault secret path for Docker credentials')
    }
    environment {
        VAULT_TOKEN = credentials('vault-token')
    }
    stages {
        stage('Checkout') {
            steps {
                git branch: "${params.GIT_BRANCH}", url: 'https://github.com/noelpatata/WalletTrackerAPI.git'
            }
        }
        stage('Load Vault Secrets') {
            steps {
                script {
                    def vaultResponse = sh(script: """
                        curl -s -H \"X-Vault-Token: ${VAULT_TOKEN}\" \"${VAULT_ADDR}/v1/${VAULT_SECRET_PATH}\"
                    """, returnStdout: true).trim()

                    env.REGISTRY = sh(script: """
                        cat <<'EOF' | jq -r '.data.data.REGISTRY_IP'
${vaultResponse}
EOF
                    """, returnStdout: true).trim()
                    env.DOCKER_USERNAME = sh(script: """
                        cat <<'EOF' | jq -r '.data.data.REGISTRY_USER'
${vaultResponse}
EOF
                    """, returnStdout: true).trim()
                    env.DOCKER_PASSWORD = sh(script: """
                        cat <<'EOF' | jq -r '.data.data.REGISTRY_PASSWORD'
${vaultResponse}
EOF
                    """, returnStdout: true).trim()
                    env.NVD_API_KEY = sh(script: """
                        cat <<'EOF' | jq -r '.data.data.NVD_API_KEY'
${vaultResponse}
EOF
                    """, returnStdout: true).trim()
                }
            }
        }
        stage('SonarQube Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner'
                    withSonarQubeEnv() {
                        sh "${scannerHome}/bin/sonar-scanner"
                    }
                }
            }
        }
        stage('Dependency Check') {
            steps {
                sh 'mkdir -p dependency-check-report'
                dependencyCheck additionalArguments: "--scan app --project wallet-tracker-api --format ALL --out dependency-check-report --nvdApiKey ${env.NVD_API_KEY}", odcInstallation: 'owasp dependency check 12.2.2'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dependency-check-report/**/*', allowEmptyArchive: true
                }
            }
        }
        stage('Terraform Init') {
            steps {
                dir('terraform') {
                    sh 'terraform init'
                }
            }
        }
        stage('Terraform Plan') {
            steps {
                dir('terraform') {
                    retry(3) {
                        sh 'terraform plan'
                    }
                }
            }
        }
        stage('Terraform Apply') {
            steps {
                dir('terraform') {
                    retry(3) {
                        sh 'terraform apply -auto-approve'
                    }
                }
            }
        }
        stage('Build Docker Image') {
            steps {
                sh 'docker build -t wallet-tracker:${IMAGE_VERSION} ./app'
            }
        }
        stage('Push Docker Image') {
            steps {
                script {
                    sh '''
                        echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin ${REGISTRY}
                        docker tag wallet-tracker ${REGISTRY}/wallet-tracker:${IMAGE_VERSION}
                        docker push ${REGISTRY}/wallet-tracker:${IMAGE_VERSION}
                        docker logout ${REGISTRY}
                    '''
                }
            }
        }
    }
}
