pipeline {
    agent any
    parameters {
        string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Branch to build')
        string(name: 'IMAGE_VERSION', defaultValue: 'latest', description: 'Docker image version tag')
        string(name: 'REGISTRY', defaultValue: '100.96.42.211', description: 'Docker registry')
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
        stage('Prepare Terraform Files') {
            steps {
                sh 'cp database/sql_schema/init.sql.template terraform/init.sql.template'
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
                sh 'docker tag wallet-tracker ${REGISTRY}/wallet-tracker:${IMAGE_VERSION}'
                sh 'docker push ${REGISTRY}/wallet-tracker:${IMAGE_VERSION}'
            }
        }
    }
}
