pipeline {
  agent any
  stages {
    stage('STEP1') {
      parallel {
        stage('STEP1') {
          steps {
            sh 'echo step1'
          }
        }

        stage('Step 1.0') {
          steps {
            sh 'echo step1.0'
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