import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JavascriptVulnDetector extends JavaScriptParserBaseListener {
    String evalRegex = "\\beval\\([^)]*\\)";

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

}
