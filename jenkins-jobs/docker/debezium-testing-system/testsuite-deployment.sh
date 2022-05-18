#!/bin/bash

source /testsuite/library.sh

DEBEZIUM_LOCATION="/testsuite/debezium"
OCP_PROJECTS="${DEBEZIUM_LOCATION}/jenkins-jobs/scripts/ocp-projects.sh"

clone_repositories --dbz-repository "${DBZ_GIT_REPOSITORY}" \
 --dbz-branch "${DBZ_GIT_BRANCH}" --strimzi-repository "${STRZ_GIT_REPOSITORY}" --strimzi-branch "${STRZ_GIT_BRANCH}" --product-build "${PRODUCT_BUILD}" --strimzi-downstream "${OCP_STRIMZI_DOWNSTREAM_URL}";
sed -i 's/namespace: .*/namespace: '"${OCP_PROJECT_DEBEZIUM}"'/' strimzi/install/cluster-operator/*RoleBinding*.yaml ;
pushd debezium || exit 1;


#prepare ocp, run tests
oc login "${OCP_URL}" -u "${OCP_USERNAME}" -p "${OCP_PASSWORD}" --insecure-skip-tls-verify=true >/dev/null ;

${OCP_PROJECTS} --project debezium-test --create

oc create -f strimzi/install/cluster-operator/ -n "${OCP_PROJECT_DEBEZIUM}" ;

oc project "${OCP_PROJECT_SQLSERVER}" && oc adm policy add-scc-to-user anyuid system:serviceaccount:"${OCP_PROJECT_SQLSERVER}":default ;
oc project "${OCP_PROJECT_MONGO}" && oc adm policy add-scc-to-user anyuid system:serviceaccount:"${OCP_PROJECT_MONGO}":default ;
oc project "${OCP_PROJECT_DB2}" && oc adm policy add-scc-to-user anyuid system:serviceaccount:"${OCP_PROJECT_DB2}":default && oc adm policy add-scc-to-user privileged system:serviceaccount:${OCP_PROJECT_DB2}:default ;


if [ -z "${TEST_VERSION_KAFKA}" ]; then
  TEST_PROPERTIES="";
else 
  TEST_PROPERTIES="-Dversion.kafka=${TEST_VERSION_KAFKA}" ;
fi 

if [ ! -z "${DBZ_CONNECT_IMAGE}" ]; then
  TEST_PROPERTIES="$TEST_PROPERTIES -Dimage.fullname=${DBZ_CONNECT_IMAGE}" ;
fi

mvn install -pl debezium-testing/debezium-testing-system -PsystemITs \
                    -Docp.username="${OCP_USERNAME}" \
                    -Docp.password="${OCP_PASSWORD}" \
                    -Docp.url="${OCP_URL}" \
                    -Docp.project.debezium="${OCP_PROJECT_DEBEZIUM}" \
                    -Docp.project.mysql="${OCP_PROJECT_MYSQL}" \
                    -Docp.project.postgresql="${OCP_PROJECT_POSTGRESQL}" \
                    -Docp.project.sqlserver="${OCP_PROJECT_SQLSERVER}" \
                    -Docp.project.mongo="${OCP_PROJECT_MONGO}" \
                    -Docp.project.db2="${OCP_PROJECT_DB2}" \
                    -Docp.pull.secret.paths="${SECRET_PATH}" \
                    -Dtest.wait.scale="${TEST_WAIT_SCALE}" \
                    -Dtest.avro.serialisation="${TEST_APICURIO_REGISTRY}" \
                    -Dimage.kc="quay.io/debezium/testing-openshift-connect:kafka-3.1.0-1.9.0-SNAPSHOT" \
                    -Dgroups="mysql & !avro & !docker" \
                    "${TEST_PROPERTIES}";

popd || exit 1;

cp debezium/debezium-testing/debezium-testing-system/target/failsafe-reports/*.xml /testsuite/logs

if [ "${DELETE_PROJECTS}" = true ] ;
then 
  delete_projects "${OCP_PROJECT_DEBEZIUM}" "${OCP_PROJECT_MYSQL}" "${OCP_PROJECT_POSTGRESQL}" "${OCP_PROJECT_SQLSERVER}" "${OCP_PROJECT_MONGO}" "${OCP_PROJECT_DB2}";
fi ;
