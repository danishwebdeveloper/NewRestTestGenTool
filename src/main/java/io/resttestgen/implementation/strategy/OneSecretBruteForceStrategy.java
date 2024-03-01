package io.resttestgen.implementation.strategy;
import io.resttestgen.core.Environment;
import io.resttestgen.core.datatype.HttpStatusCode;
import io.resttestgen.core.datatype.parameter.leaves.LeafParameter;
import io.resttestgen.core.openapi.Operation;
import io.resttestgen.core.testing.*;
import io.resttestgen.implementation.fuzzer.NominalFuzzer;
import io.resttestgen.implementation.oracle.BlockStatusCodeOracle;
import io.resttestgen.implementation.oracle.StatusCodeOracle;
import io.resttestgen.implementation.writer.ReportWriter;
import io.resttestgen.implementation.writer.RestAssuredWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static io.resttestgen.implementation.strategy.CredentialStuffingSecurityTestingStrategy.filterLoginOperations;

public class OneSecretBruteForceStrategy extends Strategy {

    private static final Logger logger = LogManager.getLogger(OneSecretBruteForceStrategy.class);
    private static final int MAX_LOGIN_ATTEMPTS = 10;

    @Override
    public void start() {
        TestRunner runner = TestRunner.getInstance();
        runner.removeInvalidStatusCode(new HttpStatusCode(429));

        List<Operation> operations = Environment.getInstance().getOpenAPI()
                .getOperations().stream().collect(Collectors.toList());
        List<Operation> loginOperations = filterLoginOperations(operations);
        if (loginOperations.isEmpty()) {
            System.out.println("No LOG_IN operations found in the OpenAPI documentation.");
            return;
        }
        for (Operation operation : loginOperations) {
            TestSequence attemptsSequence = new TestSequence();
            for (int j = 0; j < MAX_LOGIN_ATTEMPTS; j++) {
                NominalFuzzer nominalFuzzer = new NominalFuzzer(operation);
                TestSequence sequence = nominalFuzzer.generateTestSequences(1).get(0);

                LeafParameter secretTokenParam = findSecretTokenParameter((List<LeafParameter>) sequence.get(0).getFuzzedOperation().getLeaves());
                if (secretTokenParam != null) {
                    secretTokenParam.setValue("secretrandomtoken");
                }
                attemptsSequence.append(sequence);
            }
            runner.run(attemptsSequence);
            StatusCodeOracle statusCodeOracle = new StatusCodeOracle();
            statusCodeOracle.assertTestSequence(attemptsSequence);
            BlockStatusCodeOracle blockStatusCodeOracle = new BlockStatusCodeOracle();
            blockStatusCodeOracle.assertTestSequence(attemptsSequence);
            try {
                ReportWriter reportWriter = new ReportWriter(attemptsSequence);
                reportWriter.write();
                RestAssuredWriter restAssuredWriter = new RestAssuredWriter(attemptsSequence);
                restAssuredWriter.write();
            } catch (IOException e) {
                logger.warn("Could not write report to file.");
                e.printStackTrace();
            }
        }
    }
    public static LeafParameter findSecretTokenParameter(List<LeafParameter> leaves) {
        for (LeafParameter leafParam : leaves) {
            if (leafParam.getName().toString().toLowerCase().contains("token")) {
                return leafParam;
            }
        }
        return null;
    }
}
