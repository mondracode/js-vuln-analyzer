import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.io.IOException;

import java.io.*;
import java.awt.Desktop;

public class Main {
    public static void main(String[] args) throws IOException {
        try {
            File htmlFile = new File("web_export/output.html");

            PrintStream out = new PrintStream(new FileOutputStream(htmlFile));

            PrintStream console = System.out;

            System.setOut(out);

            System.out.println("<html><head>");
            System.out.println("<link rel=\"stylesheet\" type=\"text/css\" href=\"styles.css\">");
            System.out.println("</head><body>");
            System.out.println("<h1>Node.js vulnerability analyzer</h1>");
            System.out.println("<hr>");

            JavaScriptLexer lexer;
            if (args.length == 0)
                lexer = new JavaScriptLexer(CharStreams.fromFileName("input/test_case.txt"));
            else
                lexer = new JavaScriptLexer(CharStreams.fromFileName(args[0]));

            CommonTokenStream tokens = new CommonTokenStream(lexer);

            JavaScriptParser parser = new JavaScriptParser(tokens);

            ParseTree tree = parser.program();

            JavascriptVulnDetector listener = new JavascriptVulnDetector();

            ParseTreeWalker walker = new ParseTreeWalker();
            walker.walk(listener, tree);

            System.out.println("</body></html>");

            out.close();

            System.setOut(console);

            Desktop.getDesktop().browse(htmlFile.toURI());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}