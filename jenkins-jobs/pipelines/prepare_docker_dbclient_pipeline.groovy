pipeline {
    agent {
        label 'Slave'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout([
                    $class           : 'GitSCM',
                    branches         : [[name: "${BRANCH}"]],
                    userRemoteConfigs: [[url: "${REPOSITORY}"]],
                    extensions       : [[$class           : 'RelativeTargetDirectory',
                    relativeTargetDir: 'debezium']],
                ])
            }
        }

        stage('Checkout docker-images') {
            steps {
                dir('docker-images') {
                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: "${IMG_BRANCH}"]],
                        userRemoteConfigs: [[url: "${IMG_REPOSITORY}"]]
                    ])
                }
            }
        }

        stage('Push') {
            withCredentials([
                usernamePassword(credentialsId: "${QUAY_CREDENTIALS}", usernameVariable: 'QUAY_USERNAME', passwordVariable: 'QUAY_PASSWORD'),
            ]) {
                sh '''
                set -x
                dir=$(realpath ${WORKSPACE}/docker-images/docker-images/dbclient)
                cd "${WORKSPACE}/debezium"
                ./jenkins-jobs/scripts/upload-dbclient-image.sh                           \\
                    --dir="${dir}"                                              \\
                    --image-name="dbclient"                                     \\
                    --registry="quay.io" --organisation="${QUAY_ORGANISATION}"  \\
                    --dest-login="${QUAY_USERNAME}"                             \\
                    --dest-pass="${QUAY_PASSWORD}"
                '''
            }
        }
    }
}