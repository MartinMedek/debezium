freeStyleJob('prepare-docker-dbclient') {
    displayName('Docker db client prepare')
    description('Docker db client prepare')
    label('Slave')

    parameters {
        stringParam('REPOSITORY', 'https://github.com/debezium/docker-images', 'Debezium repository where the script is located')
        stringParam('BRANCH', '*/main', 'A branch/tag where the script is located')

        stringParam(IMG_REPOSITORY, '', '')
        stringParam('IMG_BRANCH', '*/main', 'A branch/tag where the dockerFile is located')

        stringParam('QUAY_CREDENTIALS', 'rh-integration-quay-creds', 'Quay.io credentials id')
        stringParam('QUAY_ORGANISATION', 'rh-integration', 'Organisation where images are copied')
    }

    scm {
        git('$REPOSITORY', '$BRANCH')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins-jobs/pipelines/downstream_prepare_pipeline.groovy'))
            sandbox()
        }
    }
}
