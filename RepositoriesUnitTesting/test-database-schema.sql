CREATE TABLE public.entities (
  -- Columns
);

ALTER TABLE ONLY public.entities
    ADD CONSTRAINT name PRIMARY KEY (name);

CREATE UNIQUE INDEX name ON public.entities USING btree (name);

CREATE OR REPLACE FUNCTION name()
    RETURNS TRIGGER AS $$
        BEGIN
            -- Body
        RETURN NEW;
    END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER name_trigger BEFORE UPDATE ON public.entities FOR EACH ROW EXECUTE PROCEDURE public.name();

ALTER TABLE ONLY public.entities
    ADD CONSTRAINT name FOREIGN KEY (name) REFERENCES public.name(name);
