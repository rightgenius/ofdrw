package org.ofdrw.converter.ofdconverter;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.ofdrw.pkg.tool.ElemCup;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * PDF → OFD 已不在本分支支持范围。<br>
 * 本次 OpenPDF 重构彻底移除了 Apache PDFBox,而 OpenPDF / iText 7 都没有
 * 等价的 PDF 页面栅格化能力 ({@code PDFRenderer}),所以 {@link PDFConverter}
 * 只能以 stub 形式存在 (调用时抛 {@link org.ofdrw.converter.GeneralConvertException})。
 * <p>
 * 该类所有用例禁用,留作历史记录;如需恢复请基于历史分支运行或接入独立
 * 的 PDF 栅格化方案 (例如 PDFium 的 JNI 封装)。
 */
@Disabled("PDF→OFD 转换在 OpenPDF 重构中暂未实现,见 PDFConverter 类注释")
class PDFConverterTest {

    @Test
    void convertFont() throws Exception {
        ElemCup.ENABLE_DEBUG_PRINT = true;
        Path src = Paths.get("src/test/resources/ff.pdf");
        Path dst = Paths.get("target/ff.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    @Test
    void convert() throws Exception {
        ElemCup.ENABLE_DEBUG_PRINT = true;
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convert.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    /**
     * 不复制附件 — stub 上该 setter 已不存在 (随 PDFBox 一并删除)。
     */
    @Test
    void convertDropAttachFile() throws Exception {
        ElemCup.ENABLE_DEBUG_PRINT = true;
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convert.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    /**
     * 不导出书签 — stub 上该 setter 已不存在 (随 PDFBox 一并删除)。
     */
    @Test
    void convertDropBookmark() throws Exception {
        ElemCup.ENABLE_DEBUG_PRINT = true;
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convert.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }


    @Test
    void convertPage2() throws Exception {
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convertPage2.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src, 0, 2);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    @Test
    void convertRecombine() throws Exception {
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convertRcombine.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src, 2, 0, 1);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    @Test
    void convertMulti() throws Exception {
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convertMulti.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src, 0);
            converter.convert(src, 2);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    @Test
    void convertRepeat() throws Exception {
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convertRepeat.ofd");
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src, 0);
            converter.convert(src, 1);
            converter.convert(src, 1);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }

    @Test
    void convertArrRange() throws Exception {
        Path src = Paths.get("src/test/resources/Test.pdf");
        Path dst = Paths.get("target/convertArrRange.ofd");
        int[] range1 = new int[]{0, 1};
        int[] range2 = new int[]{3};
        try (PDFConverter converter = new PDFConverter(dst)) {
            converter.convert(src, range1);
            converter.convert(src, range2);
        }
        System.out.println(">> " + dst.toAbsolutePath());
    }
}