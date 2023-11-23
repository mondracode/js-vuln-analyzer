import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JavascriptVulnDetector extends JavaScriptParserBaseListener {
    String evalRegex = "\\beval\\([^)]*\\)";
    Boolean hasPrototypePollution = false;

    @Override
    public void enterExpressionStatement(JavaScriptParser.ExpressionStatementContext ctx) {
        String input = ctx.getText();

        Pattern pattern = Pattern.compile(evalRegex);
        Matcher matcher = pattern.matcher(input);

        if (matcher.find()) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("The input contains an eval() call. These calls should be avoided as they allow for malicious code injection inside its parameters.");
        }
    }

    @Override
    public void enterEqualityExpression(JavaScriptParser.EqualityExpressionContext ctx) {
        String input = ctx.getText();

        if (ctx.Equals_().getText().equals("==") || ctx.Equals_().getText().equals("!=")) {
            System.out.println(input);
            System.out.println("^^^^");
            System.out.println("This input has loose comparisons. These may behave incorrectly because of type coercion and can be used maliciously.");
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
        }
    }

}
