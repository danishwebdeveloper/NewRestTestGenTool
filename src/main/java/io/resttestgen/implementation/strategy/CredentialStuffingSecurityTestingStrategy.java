package io.resttestgen.implementation.strategy;

import io.resttestgen.core.Environment;
import io.resttestgen.core.datatype.HttpStatusCode;
import io.resttestgen.core.openapi.Operation;
import io.resttestgen.core.testing.*;
import io.resttestgen.implementation.fuzzer.NominalFuzzer;
import io.resttestgen.implementation.oracle.BlockStatusCodeOracle;
import io.resttestgen.implementation.oracle.StatusCodeOracle;
import io.resttestgen.implementation.writer.ReportWriter;
import io.resttestgen.implementation.writer.RestAssuredWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class CredentialStuffingSecurityTestingStrategy extends Strategy {

    private static final Logger logger = LogManager.getLogger(CredentialStuffingSecurityTestingStrategy.class);
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final String CREDENTIALS_FILE = "login_operations.txt";

    public void start() {
        TestRunner runner = TestRunner.getInstance();
        runner.removeInvalidStatusCode(new HttpStatusCode(429));

        List<Operation> operations = Environment.getInstance().getOpenAPI().
                getOperations().stream().collect(Collectors.toList());
        List<Operation> loginOperations = filterLoginOperations(operations);
        if (loginOperations.isEmpty()) {
            System.out.println("No LOG_IN operations found in the OpenAPI documentation.");
            return;
        }

        List<String> credentialsList = readCredentials(CREDENTIALS_FILE);

        for (Operation operation : loginOperations) {
            TestSequence attemptsSequence = new TestSequence();
            for (int j = 0; j < MAX_LOGIN_ATTEMPTS; j++) {
                NominalFuzzer nominalFuzzer = new NominalFuzzer(operation);
                TestSequence sequence = nominalFuzzer.generateTestSequences(1).get(0);

                String[] parts = credentialsList.get(j % credentialsList.size()).split(":");

                adjustSequenceWithCredentials(sequence, parts);

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

    private List<String> readCredentials(String filePath) {
        List<String> credentials = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                credentials.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return credentials;
    }

    private void adjustSequenceWithCredentials(TestSequence sequence, String[] parts) {
        if (parts.length > 1) {
            sequence.get(0).getFuzzedOperation().getLeaves().stream()
                    .filter(param -> param.getName().toString().toLowerCase().contains("username"))
                    .findFirst().ifPresent(param -> param.setValue(parts[0]));

            sequence.get(0).getFuzzedOperation().getLeaves().stream()
                    .filter(param -> param.getName().toString().toLowerCase().contains("password"))
                    .findFirst().ifPresent(param -> param.setValue(parts[1]));
        } else {
            sequence.get(0).getFuzzedOperation().getLeaves().stream()
                    .filter(param -> param.getName().toString().toLowerCase().contains("token"))
                    .findFirst().ifPresent(param -> param.setValue(parts[0]));
        }
    }

    public static List<Operation> filterLoginOperations(List<Operation> operations) {
        return operations.stream()
                .filter(operation -> operation.toString().toLowerCase().contains("login"))
                .collect(Collectors.toList());
    }
}
