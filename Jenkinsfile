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
        stage('Build Docker Image') {
            steps {
                sh 'docker build -t wallet-tracker:${IMAGE_VERSION} ./app'
            }
        }
        stage('Trivy Security Scan') {
            agent {
                docker {
                    image 'aquasec/trivy:latest'
                    args "-v /var/run/docker.sock:/var/run/docker.sock -v ${WORKSPACE}/.trivy-cache:/root/.cache"
                }
            }
            steps {
                sh '''
                    mkdir -p .trivy-cache trivy-reports

                    trivy image \
                        --format json \
                        --output trivy-reports/image-report.json \
                        --severity HIGH,CRITICAL \
                        wallet-tracker:${IMAGE_VERSION}

                    trivy image \
                        --exit-code 1 \
                        --severity HIGH,CRITICAL \
                        wallet-tracker:${IMAGE_VERSION}
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/*.json', allowEmptyArchive: true
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
