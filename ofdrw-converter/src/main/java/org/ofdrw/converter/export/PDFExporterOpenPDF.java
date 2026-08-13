package org.ofdrw.converter.export;

import com.lowagie.text.Document;
import com.lowagie.text.pdf.PdfWriter;
import org.ofdrw.converter.GeneralConvertException;
import org.ofdrw.converter.OpenPdfMaker;
import org.ofdrw.reader.OFDReader;
import org.ofdrw.reader.PageInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;

/**
 * OpenPDF 实现的 OFD 转 PDF 导出器
 * <p>
 * 取代 {@link PDFExporterPDFBox}。OpenPDF 是 LGPL、无 AWT 运行时依赖，
 * 适合 native-image 打包场景。
 */
public class PDFExporterOpenPDF implements OFDExporter {

    /**
     * OFD解析器
     */
    final OFDReader ofdReader;

    /**
     * PDF文档对象
     */
    final Document pdfDoc;

    /**
     * PDF写入器
     */
    final PdfWriter pdfWriter;

    /**
     * PDF转换器
     */
    final OpenPdfMaker pdfMaker;

    /**
     * 导出流
     */
    OutputStream outputStream;

    /**
     * 导出的文件路径
     */
    Path outputPath;

    /**
     * 是否已经关闭
     */
    private boolean closed = false;

    public PDFExporterOpenPDF(Path ofdFilePath, Path pdfFilePath) throws IOException {
        ofdReader = new OFDReader(ofdFilePath);
        if (pdfFilePath == null) {
            throw new IllegalArgumentException("导出PDF路径为空");
        }
        pdfFilePath = pdfFilePath.toAbsolutePath();
        if (!Files.exists(pdfFilePath)) {
            Path parent = pdfFilePath.getParent();
            if (Files.exists(parent)) {
                if (!Files.isDirectory(parent)) {
                    throw new IllegalArgumentException("已经存在同名文件: " + parent);
                }
            } else {
                Files.createDirectories(parent);
            }
            Files.createFile(pdfFilePath);
        }
        this.outputPath = pdfFilePath;
        this.pdfDoc = new Document();
        this.pdfWriter = PdfWriter.getInstance(pdfDoc, Files.newOutputStream(pdfFilePath));
        this.pdfMaker = new OpenPdfMaker(ofdReader, pdfDoc, pdfWriter);
    }

    public PDFExporterOpenPDF(InputStream ofdInStream, OutputStream pdfOutStream) throws IOException {
        ofdReader = new OFDReader(ofdInStream);
        if (pdfOutStream == null) {
            throw new IllegalArgumentException("导出PDF流为空");
        }
        this.outputStream = pdfOutStream;
        this.pdfDoc = new Document();
        this.pdfWriter = PdfWriter.getInstance(pdfDoc, pdfOutStream);
        this.pdfMaker = new OpenPdfMaker(ofdReader, pdfDoc, pdfWriter);
    }

    @Override
    public void export(int... indexes) throws GeneralConvertException {
        try {
            List<PageInfo> targetPages = new LinkedList<>();
            if (indexes == null || indexes.length == 0) {
                targetPages.addAll(ofdReader.getPageList());
            } else {
                int maxPageIndex = ofdReader.getNumberOfPages();
                for (int index : indexes) {
                    if (index < 0 || index >= maxPageIndex) {
                        continue;
                    }
                    targetPages.add(ofdReader.getPageInfo(index));
                }
            }
            pdfDoc.open();
            for (PageInfo pageInfo : targetPages) {
                pdfMaker.makePage(pageInfo);
            }
        } catch (IOException e) {
            throw new GeneralConvertException("OFD转换PDF失败 ", e);
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;

        if (pdfMaker != null && pdfDoc != null && ofdReader != null) {
            pdfMaker.addAttachments(ofdReader);
        }
        if (pdfDoc != null && pdfDoc.isOpen()) {
            pdfDoc.close();
        }
        if (ofdReader != null) {
            ofdReader.close();
        }
    }
}
