package dto;

import java.util.List;
import java.util.Objects;

/**
 * Обгортка для списку маршрутів (використовується у GET /api/routes).
 */
public class RoutesDTO {
    private final List<RDto> items;
    private final int total;

    public RoutesDTO(List<RDto> items) {
        this.items = Objects.requireNonNull(items);
        this.total = items.size();
    }

    public List<RDto> getItems() { return items; }
    public int getTotal() { return total; }
}
