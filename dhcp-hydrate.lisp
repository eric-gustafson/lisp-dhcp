
(PROGN
 (DEFMETHOD DHCP-PACKET ((OBJ DHCP))
   (WITH-OPEN-FILE
       (OUT #P"/tmp/a" :DIRECTION :OUTPUT :ELEMENT-TYPE '(UNSIGNED-BYTE 8)
        :IF-DOES-NOT-EXIST :CREATE :IF-EXISTS :OVERWRITE)
     (WRITE-SEQ (NUMBER->OCTETS (OP OBJ) :N 1 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (HTYPE OBJ) :N 1 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (HLEN OBJ) :N 1 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (HOPS OBJ) :N 1 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (XID OBJ) :N 4 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (SECS OBJ) :N 2 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (FLAGS OBJ) :N 2 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (CIADDR OBJ) :N 4 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (YIADDR OBJ) :N 4 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (SIADDR OBJ) :N 4 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (GIADDR OBJ) :N 4 :ENDIAN :BIG) OUT)
     (WRITE-SEQ (NUMBER->OCTETS (CHADDR OBJ) :N 16 :ENDIAN :BIG) OUT)
     (WRITE-SEQUENCE (SNAME OBJ) OUT)
     (WRITE-SEQUENCE (FILE OBJ) OUT)
     (WRITE-SEQUENCE (OPTIONS OBJ) OUT))))