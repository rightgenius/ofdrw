package org.ofdrw.converter.export;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.parser.PdfContentReaderTool;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ofdrw.graphics2d.OFDGraphicsDocument;
import org.ofdrw.graphics2d.OFDPageGraphics2D;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ImageBlendModeExportTest {

    @TempDir
    Path tempDir;

    @Test
    void itextUsesNormalBlendModeForOpaqueImages() throws Exception {
        assertOpaqueImageCoversEarlierContent("itext", PDFExporterIText::new);
    }

    @Test
    void openPdfUsesNormalBlendModeForOpaqueImages() throws Exception {
        assertOpaqueImageCoversEarlierContent("openpdf", PDFExporterOpenPDF::new);
    }

    private void assertOpaqueImageCoversEarlierContent(String name, ExporterFactory factory) throws Exception {
        Path ofd = tempDir.resolve(name + ".ofd");
        Path pdf = tempDir.resolve(name + ".pdf");
        createOverlappingImageDocument(ofd);

        try (OFDExporter exporter = factory.create(ofd, pdf)) {
            exporter.export();
        }

        // OpenPDF 没有 PDFRenderer 这种像素栅格化能力;
        // 退化为结构检查:确认图片 (Do XObject) 在黑色矩形 (close+fill) 之后绘制。
        // 这等价于"不透明图像覆盖在先内容"的内容流证据。
        // 注意: OFDRW graphics2d 把 fillRect 编译成 5 点 path + close + fill,
        // 不会发出 PDF 的 `re` 操作符。
        try (PdfReader reader = new PdfReader(pdf.toAbsolutePath().toString())) {
            StringWriter sw = new StringWriter();
            try (PrintWriter pw = new PrintWriter(sw)) {
                PdfContentReaderTool.listContentStreamForPage(reader, 1, pw);
            }
            String content = sw.toString();
            // Find the filled rectangle's closePath+fill, and the image Do operator.
            // iText emits "/Im1 Do" on one line, OpenPDF emits "/img0 Do" on one line;
            // both are valid "draw image" markers. Use line suffix "Do" to match.
            int fillPos = -1;
            int doPos = -1;
            for (int i = 0; i < content.length() - 1; i++) {
                if (fillPos < 0 && content.startsWith("h\nf\n", i)) {
                    fillPos = i;
                }
                if (doPos < 0 && content.regionMatches(true, i, "do", 0, 2)
                        && (i == 0 || !Character.isLetterOrDigit(content.charAt(i - 1)))
                        && (i + 2 >= content.length() || !Character.isLetterOrDigit(content.charAt(i + 2)))) {
                    doPos = i;
                }
            }
            assertTrue(fillPos > 0, "Expected a filled shape in the content stream, was:\n" + content);
            assertTrue(doPos > fillPos,
                    "An opaque image must be drawn AFTER the rectangle (covers earlier content). Content:\n" + content);
        }
    }

    private void createOverlappingImageDocument(Path destination) throws IOException {
        BufferedImage whiteImage = new BufferedImage(20, 20, BufferedImage.TYPE_INT_RGB);
        Graphics2D imageGraphics = whiteImage.createGraphics();
        try {
            imageGraphics.setColor(Color.WHITE);
            imageGraphics.fillRect(0, 0, whiteImage.getWidth(), whiteImage.getHeight());
        } finally {
            imageGraphics.dispose();
        }

        try (OFDGraphicsDocument document = new OFDGraphicsDocument(destination)) {
            OFDPageGraphics2D page = document.newPage(100, 100);
            page.setColor(Color.BLACK);
            page.fillRect(0, 0, 100, 100);
            page.drawImage(whiteImage, 20, 20, 60, 60, null);
        }
    }

    @FunctionalInterface
    private interface ExporterFactory {
        OFDExporter create(Path ofd, Path pdf) throws IOException;
    }
}
