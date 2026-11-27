import sqlite3
import pymupdf  

PDF_PATH = "../SS_ISO_SAE_21434_2021_EN.pdf"  
DB_PATH = "iso21434.db"

def build_database():
    doc = pymupdf.open(PDF_PATH)  
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS iso_chunks")
    cursor.execute("""
        CREATE VIRTUAL TABLE iso_chunks USING fts5(
            page_num UNINDEXED,
            content
        )
    """)

    chunks_added = 0
    for page_index, page in enumerate(doc):
        text = page.get_text("text")  
        # Split page into paragraphs/sections by double newlines
        paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 60]
        
        for p in paragraphs:
            cursor.execute(
                "INSERT INTO iso_chunks (page_num, content) VALUES (?, ?)",
                (page_index + 1, p)
            )
            chunks_added += 1

    conn.commit()
    conn.close()
    print(f"Indexed {chunks_added} sections from {len(doc)} pages into {DB_PATH}.")

if __name__ == "__main__":
    build_database()