import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        System.out.println("JS vuln analyzer");
        System.out.println("----------------");

        // crear un analizador léxico
        JavaScriptLexer lexer;
        if (args.length==0)
            lexer = new JavaScriptLexer(CharStreams.fromFileName("input/test_case.txt"));
        else
            lexer = new JavaScriptLexer(CharStreams.fromFileName(args[0]));

        // Identificar al analizador léxico como fuente de tokens para el sintactico
        CommonTokenStream tokens = new CommonTokenStream(lexer);

        // Crear el analizador sintáctico que se alimenta a partir del buffer de tokens
        JavaScriptParser parser = new JavaScriptParser(tokens);

        ParseTree tree = parser.program(); // comienza el análisis en la regla inicial
        System.out.println(tree.toStringTree(parser)); // imprime el árbol en forma textual

        JavascriptVulnDetector listener = new JavascriptVulnDetector();

        ParseTreeWalker walker = new ParseTreeWalker();
        walker.walk(listener, tree);
        System.out.println();
    }
}