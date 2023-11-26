import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.io.*;
import java.awt.Desktop;

public class Main {
    public static void main(String[] args) throws IOException {
        File htmlFile = new File("web_export/output.html");

        PrintStream out = new PrintStream(new FileOutputStream(htmlFile));

        PrintStream console = System.out;

        System.setOut(out);

        System.out.println("<html><head>");
        System.out.println("<link rel=\"stylesheet\" type=\"text/css\" href=\"styles.css\">");
        System.out.println("</head><body>");
        System.out.println("<h1>Node.js vulnerability analyzer</h1>");

        File srcFolder = new File("input/src");
        processFiles(srcFolder);

        try {
            AuditService.main(args);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("</body></html>");

        out.close();

        System.setOut(console);

        Desktop.getDesktop().browse(htmlFile.toURI());
    }

    private static void processFiles(File folder) {
        File[] files = folder.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    // If it's a directory, process its files
                    processFiles(file);
                } else if (file.getName().toLowerCase().endsWith(".js")) {
                    // If it's a JavaScript file, perform analysis
                    processJsFile(file);
                }
            }
        }
    }

    private static void processJsFile(File jsFile) {
        System.out.println("<hr>");
        System.out.println("<h2>Analysis for file: " + jsFile.getPath().substring(jsFile.getPath().indexOf("input/") + 6) + "</h2>");

        try {
            JavaScriptLexer lexer = new JavaScriptLexer(CharStreams.fromFileName(jsFile.getPath()));
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            JavaScriptParser parser = new JavaScriptParser(tokens);
            ParseTree tree = parser.program();
            JavascriptVulnDetector listener = new JavascriptVulnDetector();
            ParseTreeWalker walker = new ParseTreeWalker();
            walker.walk(listener, tree);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}