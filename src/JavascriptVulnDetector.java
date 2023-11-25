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

    @Override
    public void enterExpressionStatement(JavaScriptParser.ExpressionStatementContext ctx) {
        String input = ctx.getText();

        Pattern eval_pattern = Pattern.compile("\\beval\\([^)]*\\)");
        Matcher eval_matcher = eval_pattern.matcher(input);

        Pattern tmt_pattern = Pattern.compile("\\bsetTimeout\\([^)]*\\)");
        Matcher tmt_matcher = tmt_pattern.matcher(input);

        if (eval_matcher.find()) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("This may be vulnerable to arbitrary code execution attacks because it uses the eval() function with a string argument, which can execute user input as code.");
            System.out.println("----------");
        } else if (tmt_matcher.find()) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("This may be vulnerable to arbitrary code execution attacks because it uses the setTimeout() function with a string argument, which can execute user input as code.");
            System.out.println("----------");
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

        if ((ctx.Equals_() != null && ctx.Equals_().getText().equals("==")) || (ctx.NotEquals() != null && ctx.NotEquals().getText().equals("!="))) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("This input has loose comparisons. These may behave incorrectly because of type coercion and can be used maliciously.");
            System.out.println("----------");
        }
    }

    @Override
    public void enterPropertyName(JavaScriptParser.PropertyNameContext ctx) {
        String input = ctx.getText();

        if (ctx.getText().equals("\"__proto__\"")) {
            hasPrototypePollution = true;
        }
    }

    @Override
    public void exitPropertyExpressionAssignment(JavaScriptParser.PropertyExpressionAssignmentContext ctx) {
        String input = ctx.getText();

        if (hasPrototypePollution && input.contains("\"__proto__\"")) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("This input contains prototype pollution. This can interfere with expected behavior of standard functions so not using it is advised");
            System.out.println("----------");
        }
    }

    @Override
    public void enterVariableStatement(JavaScriptParser.VariableStatementContext ctx) {
        String input = separateVarKeyword(ctx.getText());

        Pattern pattern = Pattern.compile(weakRNGRegex);
        Matcher matcher = pattern.matcher(input);

        if (matcher.find()) {
            System.out.println(matcher.group(0));
            System.out.println("^^^^");
            System.out.println("This is a weak random number generation. It is highly discouraged to use Math.random() for any critical purpose");
            System.out.println("----------");
        }

        pattern = Pattern.compile(exposedCredentialsRegex);
        matcher = pattern.matcher(input);

        if (matcher.find()) {
            System.out.println(matcher.group(0));
            System.out.println("^^^^");
            System.out.println("It is a bad practice to declare literal credentials on source code, since they could be accessed by malicious agents.");
            System.out.println("----------");
        }
    }

    @Override
    public void enterArgumentsExpression(JavaScriptParser.ArgumentsExpressionContext ctx) {
        String input = ctx.getText();

        if (input.equals("app.use(cors())")) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("Using CORS protection without an explicit whitelist is discouraged");
            System.out.println("----------");
        }
    }

    @Override
    public void enterFunctionBody(JavaScriptParser.FunctionBodyContext ctx) {
        String input = ctx.getText();

        Pattern xss_pattern = Pattern.compile("(\\$\\{.*?\\}|\\<.*?\\>|\\%3C.*?\\%3E|\\\".*?\\\"|\\'.*?\\'|\\`.*?\\`)");
        Matcher xss_matcher = xss_pattern.matcher(input);

        if (xss_matcher.find()) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("This may be vulnerable to XSS attacks because it includes user input directly in the HTML response without sanitization.");
            System.out.println("----------");
        }
    }

    @Override
    public void enterWhileStatement(JavaScriptParser.WhileStatementContext ctx) {
        if (insideEndpoint) {
            String input = ctx.getText();

            if (input.startsWith("while(true)")) {
                System.out.println(input);
                System.out.println("^^^^");
                System.out.println("This may be vulnerable to DDoS attacks because it includes a 'while (true)' loop inside an endpoint definition without any break condition.");
                System.out.println("----------");
            }
        }
    }
}