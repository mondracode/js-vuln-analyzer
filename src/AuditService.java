import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class AuditService {
    public static void main(String[] args) {
        try {
            String packageJsonPath = "./input/package.json";
            String packageJsonContent = readFile(packageJsonPath);

            String requestBody = packageJsonContent;

            URL url = new URL("https://registry.npmjs.org/-/npm/v1/security/audits");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("User-Agent", "insomnia/8.4.4");
            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = requestBody.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                processSecurityReport(response.toString());
            }



        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void processSecurityReport(String responseJson) {
        Gson gson = new Gson();
        JsonObject securityReport = gson.fromJson(responseJson, JsonObject.class);


        JsonObject metadata = securityReport.getAsJsonObject("metadata");
        JsonObject advisories = securityReport.getAsJsonObject("advisories");
        JsonArray actions = securityReport.getAsJsonArray("actions");

        generateHtmlReport(metadata, advisories, actions);
    }

    private static void generateHtmlReport(JsonObject metadata, JsonObject advisories, JsonArray actions) {
        System.out.println("<h1>Package.json Audit Results</h1>");
        System.out.println("<hr>");

        System.out.println("<div class='container'><h3>Vulnerabilities</h3>");
        System.out.println("<ul>");

        JsonElement vulnerabilitiesElement = metadata.getAsJsonObject("vulnerabilities");

        if (vulnerabilitiesElement.isJsonObject()) {
            JsonObject vulnerabilities = vulnerabilitiesElement.getAsJsonObject();

            System.out.println("<li>Info: " + vulnerabilities.get("info") + "</li>");
            System.out.println("<li>Low: " + vulnerabilities.get("low") + "</li>");
            System.out.println("<li>Moderate: " + vulnerabilities.get("moderate") + "</li>");
            System.out.println("<li>High: " + vulnerabilities.get("high") + "</li>");
            System.out.println("<li>Critical: " + vulnerabilities.get("critical") + "</li>");
        } else {
            System.out.println("<li>Unexpected value type for vulnerabilities</li>");
        }

        System.out.println("</ul></div>");
        System.out.println("<hr>");

        System.out.println("<div class='container'><h3>Advisories</h3>");
        System.out.println("<ul>");
        for (Map.Entry<String, JsonElement> entry : advisories.entrySet()) {
            String advisoryId = entry.getKey();
            JsonElement advisoryElement = entry.getValue();

            if (advisoryElement.isJsonObject()) {
                JsonObject advisory = advisoryElement.getAsJsonObject();

                System.out.println("<li>");
                System.out.println("<strong>" + advisory.get("title").getAsString() + "</strong>");
                System.out.println("<ul>");
                System.out.println("<li>Severity: " + advisory.get("severity").getAsString() + "</li>");
                System.out.println("<li>Vulnerable Versions: " + advisory.get("vulnerable_versions").getAsString() + "</li>");
                System.out.println("<li>Recommendation: " + advisory.get("recommendation").getAsString() + "</li>");
                System.out.println("</ul>");
                System.out.println("</li>");
            } else if (advisoryElement.isJsonPrimitive()) {
                System.out.println("<li>Unexpected primitive value for advisory with ID: " + advisoryId + "</li>");
            } else {
                // Handle other cases if needed
                System.out.println("<li>Unexpected value type for advisory with ID: " + advisoryId + "</li>");
            }
        }
        System.out.println("</ul></div>");
        System.out.println("<hr>");

        System.out.println("<div class='container'><h3>Actions</h3>");
        System.out.println("<ul>");
        for (int i = 0; i < actions.size(); i++) {
            JsonObject action = actions.get(i).getAsJsonObject();
            System.out.println("<li>");
            System.out.println("<strong>" + action.get("module").getAsString() + "</strong>");
            System.out.println("<ul>");
            System.out.println("<li>Action: " + action.get("action").getAsString() + "</li>");
            System.out.println("<li>Module: " + action.get("module").getAsString() + "</li>");
            System.out.println("<li>Target: " + action.get("target").getAsString() + "</li>");
            System.out.println("<li>Resolves:");
            System.out.println("<ul>");

            JsonArray resolves = action.getAsJsonArray("resolves");
            for (int j = 0; j < resolves.size(); j++) {
                JsonObject resolve = resolves.get(j).getAsJsonObject();
                System.out.println("<li>" + resolve.get("path").getAsString() + "</li>");
            }

            System.out.println("</ul></li>");
            System.out.println("</ul></div>");
            System.out.println("<hr>");
        }
    }

    private static String readFile(String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(filePath), "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line);
            }
        }
        return content.toString();
    }
}
