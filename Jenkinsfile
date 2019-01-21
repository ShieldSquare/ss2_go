try {
    node {
      //variables
      def moduleName = 'golang'

      //constants
      def project = 'shieldsquare-backend'
      def stgbucket = 'stg-ss-connector'
      def prodbucket = 'prod-ss-connector'

      // GCS Config
      def gcloud = '/usr/bin/gcloud'
      def gsutil = '/usr/bin/gsutil'
      def zone = 'us-central1-b'
      
      //:::::::::: Build Logic :::::::::::::::::://

      stage ('Clean the workspace build directory') {
          deleteDir()
      }

      //Code checkout from SCM
      checkout([
          $class: 'GitSCM',
          branches: scm.branches,
          extensions: scm.extensions + [[$class: 'CloneOption', noTags: false, reference: '', shallow: true]],
          userRemoteConfigs: scm.userRemoteConfigs
      ])

      stage("GIT INFO"){
        echo ":::::::::::GIT_BUILD_TAG::::::::::::::::::::::::"

        GIT_BUILD_TAG = sh(returnStdout: true, script: "git describe --tags HEAD").trim()
        sh("echo ${GIT_BUILD_TAG} > GIT_BUILD_TAG_${GIT_BUILD_TAG}")
        echo "GIT_BUILD_TAG :: ${GIT_BUILD_TAG}"


        echo ":::::::::::GIT_LAST_SHORT_COMMIT::::::::::::::::::::::::"

        GIT_LAST_SHORT_COMMIT = sh(returnStdout: true, script: "git log -n 1 --pretty=format:'%h'").trim()
        sh("echo ${GIT_LAST_SHORT_COMMIT} > GIT_LAST_SHORT_COMMIT_${GIT_LAST_SHORT_COMMIT}")

        echo ":::::::::::GIT_COMMITTER_EMAIL::::::::::::::::::::::::"

        GIT_COMMITTER_EMAIL = sh(returnStdout: true, script: "git show -s --pretty=%ae").trim()
        sh("echo ${GIT_COMMITTER_EMAIL} > GIT_COMMITTER_EMAIL_${GIT_COMMITTER_EMAIL}")

        echo ":::::::::::GIT_COMMITTER_NAME::::::::::::::::::::::::"

        GIT_COMMITTER_NAME = sh(returnStdout: true, script: "git show -s --pretty=%an").trim()
        sh("echo ${GIT_COMMITTER_NAME} > GIT_COMMITTER_NAME-${GIT_COMMITTER_NAME}")

      }

      //Tag used to register artifacts
      def stgbuildTag =  "${stgbucket}/${moduleName}/${GIT_BUILD_TAG}/"
      def prodbuildTag =  "${prodbucket}/${moduleName}/${GIT_BUILD_TAG}/"

      


      stage("Continuous Delivery Execution"){
        switch (env.BRANCH_NAME) {
          // Roll out to canary environment
          case "staging":

              


//Gathering resources for module
              stage("Preparation of Dockerfile dependency"){
                  echo "Copy stuffs if you like into this folder to"
                  //Copy main.py file to workplace
                  sh("mkdir ss_golang_${GIT_BUILD_TAG}")
                  sh("cp -r README.md ss2_config.json ShieldsquareCABundle.pem ss_golang_${GIT_BUILD_TAG}/")


                //uncomment below line if you are uploading the zip file more than once
                //sh("${gsutil} rm -rf gs://${stgbucket}/golang/ss_golang_${GIT_BUILD_TAG}")

                sh("${gsutil} -m cp -r ss_golang_${GIT_BUILD_TAG} gs://${stgbucket}/golang/")
              }
              
              break

          
    // Roll out to production environment

case "production":




//Gathering resources for module
              stage("Preparation of Dockerfile dependency"){
                  echo "Copy stuffs if you like into this folder to"
                  //Copy main.py file to workplace
                  sh("mkdir ss_golang_${GIT_BUILD_TAG}")
                  sh("cp -r README.md ss2_config.json ShieldsquareCABundle.pem ss_golang_${GIT_BUILD_TAG}/")
                  

                //uncomment below line if you are uploading the zip file more than once
                //sh("${gsutil} rm -rf gs://${prodbucket}/golang/ss_golang_${GIT_BUILD_TAG}")

                sh("${gsutil} -m cp -r ss_golang_${GIT_BUILD_TAG} gs://${prodbucket}/golang/")
            }

            break

          default:

              echo "Deployment came for non-(staging | production)  : ${env.BRANCH_NAME}"
        }
      }
  }
}
catch (exc) {
    
    echo 'Something failed !!!'
    throw exc

}

