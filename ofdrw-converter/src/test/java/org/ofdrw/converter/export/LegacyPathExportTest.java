package org.ofdrw.converter.export;

import com.lowagie.text.pdf.PRTokeniser;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 验证 OFD 旧版"绝对路径"导出到 PDF 时, 路径位置和线宽保持原有精度。
 * <p>
 * 原本依赖 PDFBox 的 {@code PDFStreamParser};重构后使用 OpenPDF 的
 * {@link PdfReader} + {@link PRTokeniser} 直接读 content stream 的字节,
 * 避开 {@code PdfContentReaderTool} 在 OpenPDF 1.3.39 中的渲染 bug。
 */
class LegacyPathExportTest {

    @TempDir
    Path tempDir;

    @Test
    void openPdfKeepsLegacyPathPositionAndLineWidth() throws Exception {
        assertLegacyPath(new PDFExporterFactory() {
            @Override
            public OFDExporter create(Path ofd, Path pdf) throws IOException {
                return new PDFExporterOpenPDF(ofd, pdf);
            }
        }, "openpdf");
    }

    @Test
    void iTextKeepsLegacyPathPositionAndLineWidth() throws Exception {
        assertLegacyPath(new PDFExporterFactory() {
            @Override
            public OFDExporter create(Path ofd, Path pdf) throws IOException {
                return new PDFExporterIText(ofd, pdf);
            }
        }, "itext");
    }

    private void assertLegacyPath(PDFExporterFactory factory, String name) throws Exception {
        Path ofd = tempDir.resolve(name + ".ofd");
        Path pdf = tempDir.resolve(name + ".pdf");
        createLegacyPathOFD(ofd);
        try (OFDExporter exporter = factory.create(ofd, pdf)) {
            exporter.export();
        }

        List<String> contentStream = readContentStream(pdf);
        assertEquals(1.35467d, operandBefore(contentStream, "w", 1, 0), 0.01d);
        assertEquals(456d * 72d / 300d, operandBefore(contentStream, "m", 2, 0), 0.001d);
        assertEquals(486d * 72d / 300d, operandBefore(contentStream, "l", 2, 0), 0.001d);
    }

    /**
     * 用 {@link PdfReader} + {@link PRTokeniser} 把 content stream 切成
     * "操作数 / 操作符" 形式的字符串列表。<br>
     * 这是 PDFBox {@code PDFStreamParser.getTokens()} 的最小替代,
     * 足够验证 {@code w} / {@code m} / {@code l} 等单字操作符前的数字。
     */
    private static List<String> readContentStream(Path pdf) throws IOException {
        List<String> tokens = new ArrayList<>();
        try (PdfReader reader = new PdfReader(pdf.toAbsolutePath().toString())) {
            byte[] contentBytes = reader.getPageContent(1);
            if (contentBytes == null) {
                return tokens;
            }
            // PRTokeniser consumes its buffer fully; copy first since getPageContent
            // may return a shared buffer that the reader will release on close.
            byte[] buf = contentBytes.clone();
            try (PRTokeniser tok = new PRTokeniser(buf)) {
                while (tok.nextToken()) {
                    int t = tok.getTokenType();
                    if (t == PRTokeniser.TK_ENDOFFILE) {
                        break;
                    }
                    String value = tokenToString(tok, t);
                    if (value != null) {
                        tokens.add(value);
                    }
                }
            }
        }
        return tokens;
    }

    private static String tokenToString(PRTokeniser tok, int type) {
        switch (type) {
            case PRTokeniser.TK_NUMBER:
                return tok.getStringValue();
            case PRTokeniser.TK_STRING:
                return "(" + tok.getStringValue() + ")";
            case PRTokeniser.TK_NAME:
                return "/" + tok.getStringValue();
            case PRTokeniser.TK_OTHER:
                return tok.getStringValue();
            case PRTokeniser.TK_REF:
                return tok.getStringValue();
            default:
                return null; // TK_COMMENT, TK_START_*, TK_END_* not relevant here
        }
    }

    private static double operandBefore(List<String> tokens, String operator, int operandCount, int operandIndex) {
        for (int i = 0; i < tokens.size(); i++) {
            if (operator.equals(tokens.get(i))) {
                int operandPos = i - operandCount + operandIndex;
                return Double.parseDouble(tokens.get(operandPos));
            }
        }
        throw new AssertionError("Missing PDF operator: " + operator + " in tokens: " + tokens);
    }

    private static void createLegacyPathOFD(Path output) throws IOException {
        try (ZipOutputStream zip = new ZipOutputStream(java.nio.file.Files.newOutputStream(output))) {
            put(zip, "OFD.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<ofd:OFD xmlns:ofd=\"http://www.ofdspec.org\" Version=\"1.0\" DocType=\"OFD\">"
                    + "<ofd:DocBody><ofd:DocInfo><ofd:DocID>legacy-path-test</ofd:DocID>"
                    + "<ofd:Creator>Foxit OFD Creator</ofd:Creator></ofd:DocInfo>"
                    + "<ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot></ofd:DocBody></ofd:OFD>");
            put(zip, "Doc_0/Document.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<ofd:Document xmlns:ofd=\"http://www.ofdspec.org\"><ofd:CommonData>"
                    + "<ofd:PageArea><ofd:PhysicalBox>0 0 210 297</ofd:PhysicalBox></ofd:PageArea>"
                    + "<ofd:MaxUnitID>3</ofd:MaxUnitID></ofd:CommonData><ofd:Pages>"
                    + "<ofd:Page ID=\"1\" BaseLoc=\"Pages/Page_0/Content.xml\"/>"
                    + "</ofd:Pages></ofd:Document>");
            put(zip, "Doc_0/Pages/Page_0/Content.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<ofd:Page xmlns:ofd=\"http://www.ofdspec.org\"><ofd:Content><ofd:Layer ID=\"2\">"
                    + "<ofd:PathObject ID=\"3\" CTM=\"0.010948 0 0 0.010925 -6.688669 -5.418684\" "
                    + "Boundary=\"38.438663 146.473328 2.963333 0.423333\" LineWidth=\"1.35467\" "
                    + "Join=\"Round\" Cap=\"Round\"><ofd:AbbreviatedData>M 456 1732 L 486 1732"
                    + "</ofd:AbbreviatedData></ofd:PathObject></ofd:Layer></ofd:Content></ofd:Page>");
        }
    }

    private static void put(ZipOutputStream zip, String name, String content) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private interface PDFExporterFactory {
        OFDExporter create(Path ofd, Path pdf) throws IOException;
    }
}
