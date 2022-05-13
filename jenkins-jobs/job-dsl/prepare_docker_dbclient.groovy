pipelineJob('prepare-docker-dbclient') {
    displayName('Docker db client prepare')
    description('Docker db client prepare')

    properties {
        githubProjectUrl('https://github.com/debezium/debezium')
    }

    parameters {
        stringParam('REPOSITORY', 'https://github.com/debezium/debezium', 'Debezium repository where the script is located')
        stringParam('BRANCH', '*/main', 'A branch/tag where the script is located')

        stringParam('IMG_REPOSITORY', 'https://github.com/debezium/docker-images', 'Debezium docker-images repository')
        stringParam('IMG_BRANCH', '*/main', 'A branch/tag where the dockerFile is located')

        stringParam('QUAY_CREDENTIALS', 'rh-integration-quay-creds', 'Quay.io credentials id')
        stringParam('QUAY_ORGANISATION', 'rh-integration', 'Organisation where images are copied')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins-jobs/pipelines/prepare_docker_dbclient_pipeline.groovy'))
            sandbox()
        }
    }
}
