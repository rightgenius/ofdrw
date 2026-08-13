package org.ofdrw.converter;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.lowagie.text.Document;
import org.ofdrw.converter.export.PDFExporterIText;
import org.ofdrw.converter.export.PDFExporterOpenPDF;
import org.ofdrw.reader.OFDReader;
import org.ofdrw.reader.PageInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * PDF 转换 工具
 *
 * @author minghu.zhang
 * @since 12:53 2020/11/14
 **/
public class ConvertHelper {

    private final static Logger logger = LoggerFactory.getLogger(ConvertHelper.class);

    /**
     * 转换使用库名称
     * <p>
     * OpenPDF（LGPL）是默认选项。{@link #useIText()} 切换到 iText 7（AGPL）。
     */
    public static Lib lib = Lib.OpenPDF;

    public static enum Lib {
        OpenPDF, iText
    }

    /**
     * 使用 OpenPDF（LGPL）作为转换实现
     */
    public static void useOpenPDF() {
        lib = Lib.OpenPDF;
    }

    /**
     * 使用 iText 7（AGPL）作为转换实现
     */
    public static void useIText() {
        lib = Lib.iText;
    }

    /**
     * OFD转换PDF
     * <p>
     *
     * @param input  OFD文件路径，支持InputStream、Path、File、String（文件路径）
     * @param output PDF输出流，支持OutputStream、Path、File、String（文件路径）
     * @throws IllegalArgumentException 参数错误
     * @throws GeneralConvertException  文档转换过程中异常
     * @deprecated 不建议使用该方法，建议使用 {@link  #toPdf(Path, Path)} 系列明确参数方法。
     */
    @Deprecated
    public static void ofd2pdf(Object input, Object output) {
        try {
            if (lib == Lib.OpenPDF) {
                ofd2pdfViaOpenPDF(input, output);
            } else {
                ofd2pdfViaIText(input, output);
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            logger.error("convert to pdf failed", e);
            throw new GeneralConvertException(e);
        }
    }

    private static void ofd2pdfViaOpenPDF(Object input, Object output) throws Exception {
        // Path-based dispatch is cleanest: write to a file if needed, then read back.
        if (output instanceof Path) {
            runOpenPDF(input, (Path) output);
            return;
        }
        if (output instanceof File) {
            runOpenPDF(input, ((File) output).toPath());
            return;
        }
        if (output instanceof String) {
            runOpenPDF(input, Path.of((String) output));
            return;
        }
        // OutputStream: write to a temp PDF, then copy bytes to the stream.
        Path tmp = Files.createTempFile("ofdrw-", ".pdf");
        try {
            runOpenPDF(input, tmp);
            try (OutputStream out = (OutputStream) output) {
                Files.copy(tmp, out);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static void runOpenPDF(Object input, Path outPath) throws Exception {
        if (input instanceof Path) {
            try (PDFExporterOpenPDF exporter = new PDFExporterOpenPDF((Path) input, outPath)) {
                exporter.export();
            }
        } else if (input instanceof File) {
            try (PDFExporterOpenPDF exporter = new PDFExporterOpenPDF(((File) input).toPath(), outPath)) {
                exporter.export();
            }
        } else if (input instanceof String) {
            try (PDFExporterOpenPDF exporter = new PDFExporterOpenPDF(Path.of((String) input), outPath)) {
                exporter.export();
            }
        } else if (input instanceof InputStream) {
            try (PDFExporterOpenPDF exporter = new PDFExporterOpenPDF((InputStream) input, Files.newOutputStream(outPath))) {
                exporter.export();
            }
        } else {
            throw new IllegalArgumentException("不支持的输入格式(input)，仅支持InputStream、Path、File、String");
        }
    }

    private static void ofd2pdfViaIText(Object input, Object output) throws Exception {
        OFDReader reader = openReader(input);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (PdfWriter pdfWriter = new PdfWriter(bos);
             PdfDocument pdfDocument = new PdfDocument(pdfWriter)) {
            int pageNum = 1;
            ItextMaker pdfMaker = new ItextMaker(reader);
            for (PageInfo pageInfo : reader.getPageList()) {
                long start = System.currentTimeMillis();
                pdfMaker.makePage(pdfDocument, pageInfo);
                logger.debug(String.format("page %d speed time %d", pageNum++, System.currentTimeMillis() - start));
            }
            pdfMaker.addAttachments(pdfDocument, reader);
        } finally {
            try {
                reader.close();
            } catch (IOException ignored) {
            }
        }

        if (output instanceof OutputStream) {
            bos.writeTo((OutputStream) output);
        } else if (output instanceof File) {
            try (FileOutputStream fileOutputStream = new FileOutputStream((File) output)) {
                bos.writeTo(fileOutputStream);
            }
        } else if (output instanceof String) {
            try (FileOutputStream fileOutputStream = new FileOutputStream((String) output)) {
                bos.writeTo(fileOutputStream);
            }
        } else if (output instanceof Path) {
            try (OutputStream out = Files.newOutputStream((Path) output)) {
                bos.writeTo(out);
            }
        } else {
            throw new IllegalArgumentException("不支持的输出格式(output)，仅支持OutputStream、Path、File、String");
        }
    }

    private static OFDReader openReader(Object input) throws IOException {
        if (input instanceof InputStream) {
            return new OFDReader((InputStream) input);
        }
        if (input instanceof Path) {
            return new OFDReader((Path) input);
        }
        if (input instanceof File) {
            return new OFDReader(((File) input).toPath());
        }
        if (input instanceof String) {
            return new OFDReader((String) input);
        }
        throw new IllegalArgumentException("不支持的输入格式(input)，仅支持InputStream、Path、File、String");
    }

    /**
     * 转PDF
     */
    public static void toPdf(InputStream input, OutputStream output) {
        ofd2pdf(input, output);
    }

    public static void toPdf(InputStream input, File output) {
        ofd2pdf(input, output);
    }

    public static void toPdf(InputStream input, String output) {
        ofd2pdf(input, output);
    }

    public static void toPdf(Path input, OutputStream output) {
        ofd2pdf(input, output);
    }

    public static void toPdf(Path input, File output) {
        ofd2pdf(input, output);
    }

    public static void toPdf(Path input, Path output) {
        ofd2pdf(input, output);
    }

    /**
     * 转PDF，源文件目录为已经解压的OFD根目录
     */
    public static void toPdf(String unzippedPathRoot, String output, boolean deleteOnClose) {
        Path outPath = Path.of(output);
        // For unzipped OFD trees, the simplest portable approach is to drive OpenPdfMaker
        // directly through OFDReader (no need to re-zip the directory).
        try (OFDReader reader = new OFDReader(unzippedPathRoot, deleteOnClose)) {
            Path tempPdf = Files.createTempFile("ofdrw-", ".pdf");
            try (OutputStream out = Files.newOutputStream(tempPdf)) {
                Document pdfDoc = new Document();
                try (com.lowagie.text.pdf.PdfWriter writer = com.lowagie.text.pdf.PdfWriter.getInstance(pdfDoc, out)) {
                    OpenPdfMaker maker = new OpenPdfMaker(reader, pdfDoc, writer);
                    pdfDoc.open();
                    for (PageInfo pageInfo : reader.getPageList()) {
                        maker.makePage(pageInfo);
                    }
                    maker.addAttachments(reader);
                } finally {
                    if (pdfDoc.isOpen()) {
                        pdfDoc.close();
                    }
                }
            }
            try {
                Files.move(tempPdf, outPath, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                Files.deleteIfExists(tempPdf);
                throw e;
            }
        } catch (Exception e) {
            logger.error("convert to pdf failed", e);
            throw new GeneralConvertException(e);
        }
    }

    /**
     * 转HTML
     */
    public static void toHtml(OFDReader ofdReader, String output, int screenWidth) throws IOException {
        HtmlMaker htmlMaker = new HtmlMaker(ofdReader, output, screenWidth);
        htmlMaker.parse();
    }

    public static void toHtml(Path ofdIn, Path htmlOut, int screenWidth) throws IOException {
        try (OFDReader reader = new OFDReader(ofdIn)) {
            HtmlMaker htmlMaker = new HtmlMaker(reader, htmlOut.toAbsolutePath().toString(), screenWidth);
            htmlMaker.parse();
        }
    }
}
