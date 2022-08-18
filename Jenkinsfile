pipeline {
  agent {
    node {
      label 'LB'
    }

  }
  stages {
    stage('STEP1') {
      parallel {
        stage('STEP1') {
          steps {
            sh 'echo step1'
          }
        }

        stage('STEP 1.1') {
          steps {
            mail(subject: 'STEP 1.1', body: 'DONE', from: 'TEST@digitalitangels.com', replyTo: 'TEST@digitalitangels.com', to: 'sami.ezzerouali@hotmail.com')
          }
        }

      }
    }

    stage('final') {
      steps {
        build 'post_weather'
      }
    }

  }
}