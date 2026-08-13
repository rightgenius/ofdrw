package org.ofdrw.converter;

import org.junit.jupiter.api.Test;
import org.ofdrw.converter.point.TextCodePoint;
import org.ofdrw.core.basicStructure.pageObj.layer.block.TextObject;
import org.ofdrw.core.basicType.ST_Array;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 验证 {@link OpenPdfMaker#textMatrix} 把 OFD 文本对象参数转换为 PDF
 * 文本矩阵 6 元组 (a, b, c, d, e, f) 的正确性。
 * <p>
 * 替代原 {@code PdfboxMakerTextMatrixTest};原版的实现依赖
 * {@code org.apache.pdfbox.util.Matrix},本次重构后该类已删除。
 */
class OpenPdfMakerTextMatrixTest {

    private static final float EPSILON = 0.000001f;

    @Test
    void shouldBuildPdfTextMatrixFromOfdCtm() {
        TextObject textObject = new TextObject(1);
        textObject.setCTM(new ST_Array(
                2, 3,
                4, 5,
                10, 20
        ));
        textObject.setHScale(0.5);

        TextCodePoint point = new TextCodePoint(123, 456, "A");

        float[] matrix = OpenPdfMaker.textMatrix(textObject, point);

        assertEquals(6, matrix.length, "Text matrix must have 6 elements");
        assertEquals(1f, matrix[0], EPSILON, "scaleX (a)");
        assertEquals(-1.5f, matrix[1], EPSILON, "shearY (b)");
        assertEquals(-4f, matrix[2], EPSILON, "shearX (c)");
        assertEquals(5f, matrix[3], EPSILON, "scaleY (d)");
        assertEquals(123f, matrix[4], EPSILON, "translateX (e)");
        assertEquals(456f, matrix[5], EPSILON, "translateY (f)");
    }
}
