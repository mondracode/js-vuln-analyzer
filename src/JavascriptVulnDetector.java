import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JavascriptVulnDetector extends JavaScriptParserBaseListener {
    String weakRNGRegex = "\\S+\\s*=\\s*Math\\.random\\(\\)";
    String exposedCredentialsRegex = "(let|var|const)\\s*(username|password|api_key|apiKey)\\s*=\\s*(\"[^\"]*\"|'[^']*')";
    Boolean hasPrototypePollution = false;
    Boolean insideEndpoint = false;

    private String separateVarKeyword(String exp) {
        return exp.replaceFirst("^(const|var|let)", "$1 ");
    }

    // !TODO: Escape other HTML tags
    public static String escapeHTMLTags(String input) {
        input = input.replace("<", "&lt;");
        input = input.replace(">", "&gt;");
        return input;
    }

    @Override
    public void enterExpressionStatement(JavaScriptParser.ExpressionStatementContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        Pattern eval_pattern = Pattern.compile("\\beval\\([^)]*\\)");
        Matcher eval_matcher = eval_pattern.matcher(input);

        Pattern tmt_pattern = Pattern.compile("\\bsetTimeout\\([^)]*\\)");
        Matcher tmt_matcher = tmt_pattern.matcher(input);

        int lineNumber = ctx.getStart().getLine();

        if (eval_matcher.find()) {
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This may be vulnerable to arbitrary code execution attacks because it uses the eval() function with a string argument, which can execute user input as code.</strong></p>");
            System.out.println("<hr>");
        } else if (tmt_matcher.find()) {
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This may be vulnerable to arbitrary code execution attacks because it uses the setTimeout() function with a string argument, which can execute user input as code.</strong></p>");
            System.out.println("<hr>");
        }

        if (input.startsWith("app.get")) {
            insideEndpoint = true;
        }
    }

    @Override
    public void exitExpressionStatement(JavaScriptParser.ExpressionStatementContext ctx) {
        insideEndpoint = false;
    }

    @Override
    public void enterEqualityExpression(JavaScriptParser.EqualityExpressionContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        if ((ctx.Equals_() != null && ctx.Equals_().getText().equals("==")) || (ctx.NotEquals() != null && ctx.NotEquals().getText().equals("!="))) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This input has loose comparisons. These may behave incorrectly because of type coercion and can be used maliciously.</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterPropertyName(JavaScriptParser.PropertyNameContext ctx) {
        if (ctx.getText().equals("\"__proto__\"")) {
            hasPrototypePollution = true;
        }
    }

    @Override
    public void exitPropertyExpressionAssignment(JavaScriptParser.PropertyExpressionAssignmentContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        if (hasPrototypePollution && input.contains("\"__proto__\"")) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This input contains prototype pollution. This can interfere with expected behavior of standard functions so not using it is advised</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterVariableStatement(JavaScriptParser.VariableStatementContext ctx) {
        String input = separateVarKeyword(ctx.getText());
        input = escapeHTMLTags(input);

        Pattern pattern = Pattern.compile(weakRNGRegex);
        Matcher matcher = pattern.matcher(input);

        if (matcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + matcher.group(0) + "</code><br>");
            System.out.println("<strong>This is a weak random number generation. It is highly discouraged to use Math.random() for any critical purpose</strong></p>");
            System.out.println("<hr>");
        }

        pattern = Pattern.compile(exposedCredentialsRegex);
        matcher = pattern.matcher(input);

        if (matcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + matcher.group(0) + "</code><br>");
            System.out.println("<strong>It is a bad practice to declare literal credentials on source code, since they could be accessed by malicious agents.</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterArgumentsExpression(JavaScriptParser.ArgumentsExpressionContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        if (input.equals("app.use(cors())")) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>Using CORS protection without an explicit whitelist is discouraged</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterFunctionBody(JavaScriptParser.FunctionBodyContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        Pattern xss_pattern = Pattern.compile("(\\$\\{.*?\\}|\\<.*?\\>|\\%3C.*?\\%3E|\\\".*?\\\"|\\'.*?\\'|\\`.*?\\`)");
        Matcher xss_matcher = xss_pattern.matcher(input);

        if (xss_matcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This may be vulnerable to XSS attacks because it includes user input directly in the HTML response without sanitization.</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterWhileStatement(JavaScriptParser.WhileStatementContext ctx) {
        if (insideEndpoint) {
            String input = ctx.getText();
            input = escapeHTMLTags(input);

            if (input.startsWith("while(true)")) {
                int lineNumber = ctx.getStart().getLine();
                System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
                System.out.println("<strong>This may be vulnerable to DDoS attacks because it includes a 'while (true)' loop inside an endpoint definition without any break condition.</strong></p>");
                System.out.println("<hr>");
            }
        }
    }

    @Override
    public void enterVariableDeclaration(JavaScriptParser.VariableDeclarationContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        Pattern weakCipherPattern = Pattern.compile("\\bCryptoJS\\.DES\\.encrypt\\([^)]*\\)");
        Matcher weakCipherMatcher = weakCipherPattern.matcher(input);

        if (weakCipherMatcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This may be vulnerable to weak encryption (DES). Consider using stronger encryption algorithms.</strong></p>");
            System.out.println("<hr>");
        }

        Pattern credentialsPattern = Pattern.compile("(let|var|const)\\s*(password|token)\\s*=\\s*(\"[^\"]*\"|'[^']*')");
        Matcher credentialsMatcher = credentialsPattern.matcher(input);

        if (credentialsMatcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>It is a bad practice to declare literal credentials in the source code, as they could be accessed by malicious agents.</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterIfStatement(JavaScriptParser.IfStatementContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        Pattern insecureComparisonPattern = Pattern.compile("\\b(md5|sha1|sha256|etc)\\([^)]*\\)\\s*(==|!=)\\s*\"[^\"]*\"");
        Matcher insecureComparisonMatcher = insecureComparisonPattern.matcher(input);

        if (insecureComparisonMatcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>This may be vulnerable to insecure hash comparison. Use a secure comparison method for cryptographic operations.</strong></p>");
            System.out.println("<hr>");
        }
    }

    @Override
    public void enterFunctionDeclaration(JavaScriptParser.FunctionDeclarationContext ctx) {
        String input = ctx.getText();
        input = escapeHTMLTags(input);

        Pattern sessionPattern = Pattern.compile("function\\s*createSession\\(\\)");
        Matcher sessionMatcher = sessionPattern.matcher(input);

        if (sessionMatcher.find()) {
            int lineNumber = ctx.getStart().getLine();
            System.out.println("<p>Line " + lineNumber + ": <code>" + input + "</code><br>");
            System.out.println("<strong>Check the security of the session management functions.</strong></p>");
            System.out.println("<hr>");
        }
    }
}