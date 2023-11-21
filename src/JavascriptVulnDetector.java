public class JavascriptVulnDetector extends JavaScriptParserBaseListener {

    @Override
    public void enterExpressionSequence(JavaScriptParser.ExpressionSequenceContext ctx) {
        if (ctx.getText().equals("eval")) {
            System.out.println("omg");
        }
    }

}
