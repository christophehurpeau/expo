import { queryClient } from '../../providers/QueryProvider';
import { Update } from '../../queries/useUpdatesForBranch';
import { render, waitFor, act, fireEvent, mockGraphQLResponse } from '../../test-utils';
import { UpdatesScreen } from '../UpdatesScreen';

jest.mock('graphql-request', () => {
  return {
    GraphQLClient(apiUrl: string) {
      return {
        request: jest.fn(),
      };
    },
    gql: jest.fn(),
  };
});


function mockUpdatesResponse(updates: Update[]) {
  return mockGraphQLResponse({
    app: {
      byId: {
        updateBranchByName: {
          updates,
        },
      },
    },
  });
}

describe('<UpdatesScreen />', () => {
  beforeEach(() => {
    queryClient.clear();
  });

  test('render', async () => {
    const mockNavigation: any = {
      navigate: jest.fn(),
    };

    render(
      <UpdatesScreen
        navigation={mockNavigation}
        route={{ key: '1', name: 'Updates', params: { branchName: 'joe' } }}
      />
    );

    // necessary to avoid react update outside of act() warning
    await act(async () => {});
  });

  test('eas update row press', async () => {
    const mockNavigation: any = {
      navigate: jest.fn(),
    };

    const testUpdate: Update = {
      id: '123',
      runtimeVersion: '1',
      createdAt: new Date().toISOString(),
      message: 'hi joe',
    };

    mockUpdatesResponse([testUpdate]);

    const { queryByText, getByText } = render(
      <UpdatesScreen
        navigation={mockNavigation}
        route={{ key: '1', name: 'Updates', params: { branchName: 'joe' } }}
      />
    );

    await act(async () => {
      expect(queryByText(/hi joe/i)).toBe(null);
      await waitFor(() => getByText(/hi joe/i));

      // TODO - mock launchUpdateAsync() and ensure it is called
      fireEvent.press(getByText(/hi joe/i));
    });
  });

  test('empty state', async () => {
    const mockNavigation: any = {
      navigate: jest.fn(),
    };

    mockUpdatesResponse([]);

    const { queryByText, getByText } = render(
      <UpdatesScreen
        navigation={mockNavigation}
        route={{ key: '1', name: 'Updates', params: { branchName: 'joe' } }}
      />
    );

    await act(async () => {
      expect(queryByText(/branch has no published updates/i)).toBe(null);
      await waitFor(() => getByText(/branch has no published updates/i));
    });
  });

  test.todo('shows error toast');
});
