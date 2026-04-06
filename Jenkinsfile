pipeline {
    agent any
    parameters {
        string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Branch to build')
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
    }
}
