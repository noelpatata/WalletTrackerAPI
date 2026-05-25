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
                dependencyCheck additionalArguments: '--scan app --project wallet-tracker-api --format ALL --out dependency-check-report', odcInstallation: 'owasp dependency check 12.2.2'
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
                        # Fetch credentials from Vault
                        VAULT_RESPONSE=$(curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" \
                          "${VAULT_ADDR}/v1/${VAULT_SECRET_PATH}")
                        
                        REGISTRY=$(echo $VAULT_RESPONSE | jq -r '.data.data.REGISTRY_IP')
                        DOCKER_USERNAME=$(echo $VAULT_RESPONSE | jq -r '.data.data.REGISTRY_USER')
                        DOCKER_PASSWORD=$(echo $VAULT_RESPONSE | jq -r '.data.data.REGISTRY_PASSWORD')
                        
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
